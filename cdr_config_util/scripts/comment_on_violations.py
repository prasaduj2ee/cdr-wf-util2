import os
import xml.etree.ElementTree as ET
import requests
import json
from collections import defaultdict
import re

# --- Environment Variables ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
COMMIT_SHA = os.getenv("COMMIT_SHA")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
PR_NUMBER = os.getenv("PR_NUMBER")

HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

# --- API Endpoints ---
PR_REVIEW_COMMENTS_API = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/pulls/{PR_NUMBER}/comments"
PR_GENERAL_COMMENTS_API = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/issues/{PR_NUMBER}/comments"

# --- Store comment data ---
DIFF_LINES = {}
GENERAL_COMMENTS = defaultdict(lambda: defaultdict(list))  # file_path -> severity -> messages
POSTED_INLINE = set()
VIOLATIONS_FOUND = False

# --- Fetch PR diff and map line -> position
def get_pr_diff_lines():
    url = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/pulls/{PR_NUMBER}/files"
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        print(f"❌ Failed to fetch PR diff: {response.status_code}")
        return {}

    result = {}
    for file in response.json():
        path = file["filename"]
        patch = file.get("patch", "")
        position = 0
        positions = {}
        new_line = None

        for line in patch.splitlines():
            position += 1
            if line.startswith("@@"):
                m = re.search(r"\+(\d+)(?:,(\d+))?", line)
                if m:
                    new_start = int(m.group(1))
                    new_line = new_start - 1
                else:
                    new_line = None
            elif line.startswith("+") and not line.startswith("+++"):
                if new_line is not None:
                    new_line += 1
                    positions[new_line] = position
            elif not line.startswith("-"):
                if new_line is not None:
                    new_line += 1

        result[path] = positions
    return result

DIFF_LINES = get_pr_diff_lines()
print("DIFF_LINES-->", DIFF_LINES)

# --- Severity Mappers ---
def get_pmd_severity(priority):
    try:
        p = int(priority)
    except:
        return "Unknown"
    return {1: "High", 2: "High", 3: "Medium", 4: "Low", 5: "Info"}.get(p, "Unknown")

def get_checkstyle_severity(sev):
    return {
        "error": "High",
        "warning": "Medium",
        "info": "Info"
    }.get(sev.lower(), "Unknown")

# --- Checkstyle Rule URL ---
def get_checkstyle_url(source):
    if not source:
        return ""
    parts = source.split(".")
    if "checks" in parts:
        idx = parts.index("checks")
        if idx + 1 < len(parts):
            cat = parts[idx + 1]
            rule = parts[-1].replace("Check", "")
            return f"https://checkstyle.sourceforge.io/config_{cat}.html#{rule}"
    return "https://checkstyle.sourceforge.io/checks.html"

# --- Post inline or fallback to general comment ---
def post_inline_comment(file_path, line, message, severity="Unknown", total_issues=1):
    file_path = file_path.strip()
    line_num = int(line) if line and line.isdigit() else None
    path_in_diff = DIFF_LINES.get(file_path, {})

    if not (line_num and line_num in path_in_diff):
        #print(f"Skipping comment for {file_path}:{line} - line not in diff")
        return

    # Add current message first
    GENERAL_COMMENTS[file_path][severity].append(f"Line {line}: {message}")

    #total_issues = sum(len(v) for v in GENERAL_COMMENTS[file_path].values())
    print(f"Total issues for {file_path}: {total_issues}")

    if file_path not in POSTED_INLINE:
        if total_issues > 1:
            message += (
                "\n\n**Note**: For more comments, see the "
                f"*Static Analysis Results* section below for `{file_path}`."
            )

        payload = {
            "body": message,
            "commit_id": COMMIT_SHA,
            "path": file_path,
            "line": line_num,
            "position": 1
        }

        #print(f"Posting inline comment:\n{json.dumps(payload, indent=2)}")
        response = requests.post(PR_REVIEW_COMMENTS_API, headers=HEADERS, json=payload)
        #print(f"Inline response {response.status_code}")
        if response.status_code == 201:
            POSTED_INLINE.add(file_path)
        else:
            print(response.text)
    #else:
        #print(f"Inline comment already posted for {file_path}, skipping inline post.")

# --- General PR comment posting ---
def post_general_comments():
    for file_path, severity_map in GENERAL_COMMENTS.items():
        if not any(severity_map.values()):
            continue  # Skip files with no collected messages

        comment_body = f"### 🧹 Static Analysis Results for `{file_path}`\n"
        for severity in ["High", "Medium", "Low", "Info", "Unknown"]:
            messages = severity_map.get(severity)
            if messages:
                comment_body += f"\n<details><summary>🔸 **{severity} Severity** ({len(messages)} issue(s))</summary>\n\n"
                for m in messages:
                    comment_body += f"- {m}\n"
                comment_body += "\n</details>\n"
        payload = { "body": comment_body }
        print(f"📋 General PR comment:\n{json.dumps(payload, indent=2)}")
        r = requests.post(PR_GENERAL_COMMENTS_API, headers=HEADERS, json=payload)
        print(f"🗣️ General comment response: {r.status_code}")
        if r.status_code != 201:
            print(r.text)

# --- Parse Checkstyle report ---
def parse_checkstyle(path):
    if not os.path.exists(path):
        print(f"⚠️ Checkstyle report not found: {path}")
        return
    tree = ET.parse(path)
    root = tree.getroot()
    for f in root.findall("file"):
        file_path = f.get("name")
        file_path = file_path[file_path.find("src/"):] if "src/" in file_path else file_path
        errors = f.findall("error")
        total_errors = len(errors)
        global VIOLATIONS_FOUND
        if errors:          
            VIOLATIONS_FOUND = True
        for err in errors:
            line = err.get("line")
            severity_raw = err.get("severity", "info")
            severity = get_checkstyle_severity(severity_raw)
            source = err.get("source")
            url = get_checkstyle_url(source)
            category = "unknown"
            parts = source.split(".") if source else []
            if "checks" in parts:
                idx = parts.index("checks")
                if idx + 1 < len(parts):
                    category = parts[idx + 1].title()
            msg = f"[Checkstyle -> {category} -> {severity}] {err.get('message')} ([Reference]({url}))"
            post_inline_comment(file_path, line, msg, severity, total_errors)

# --- Parse PMD report ---
def parse_pmd(path):
    if not os.path.exists(path):
        print(f"⚠️ PMD report not found: {path}")
        return
    tree = ET.parse(path)
    root = tree.getroot()
    ns = {'ns': root.tag.split('}')[0].strip('{')} if root.tag.startswith('{') else {}
    files = root.findall("ns:file", ns) if ns else root.findall("file")
    for f in files:
        file_path = f.get("name")
        file_path = file_path[file_path.find("src/"):] if "src/" in file_path else file_path
        violations = f.findall("ns:violation", ns) if ns else f.findall("violation")
        total_violations = len(violations)
        global VIOLATIONS_FOUND
        if violations:          
            VIOLATIONS_FOUND = True
        for v in violations:
            line = v.get("beginline")
            priority = v.get("priority", "3")
            severity = get_pmd_severity(priority).title()
            ruleset = v.get("ruleset", "unknown").title()
            url = v.get("externalInfoUrl", "")
            msg_text = v.text.strip()
            msg = f"[PMD -> {ruleset} -> {severity}] {msg_text} ([Reference]({url}))" if url else f"[PMD:{severity}][{ruleset}] {msg_text}"
            post_inline_comment(file_path, line, msg, severity, total_violations)

# --- Run everything ---
parse_checkstyle("build/reports/checkstyle/main.xml")
parse_pmd("build/reports/pmd/main.xml")
post_general_comments()
if VIOLATIONS_FOUND:
    print("❌ Static analysis violations detected. Failing the CI job.")
    exit(1)  # Non-zero exit code prevents merge
else:
    print("✅ No static analysis violations found.")
