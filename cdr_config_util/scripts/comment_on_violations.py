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

PR_REVIEW_COMMENTS_API = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/pulls/{PR_NUMBER}/comments"
PR_GENERAL_COMMENTS_API = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/issues/{PR_NUMBER}/comments"

DIFF_LINES = {}
GENERAL_COMMENTS = defaultdict(lambda: defaultdict(dict))
POSTED_INLINE = set()

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
                new_line = int(m.group(1)) - 1 if m else None
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

def get_pmd_severity(priority):
    try:
        p = int(priority)
    except:
        return "Unknown"
    return {1: "High", 2: "High", 3: "Medium", 4: "Low", 5: "Info"}.get(p, "Unknown")

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

def post_inline_comment(file_path, line, message, tool):
    file_path = file_path.strip()
    line_num = int(line) if line else None
    path_in_diff = DIFF_LINES.get(file_path, {})

    existing_messages = GENERAL_COMMENTS[file_path][line_num]

    if "PMD" in existing_messages and tool != "PMD":
        return
    if tool in existing_messages and message == existing_messages[tool]:
        return
    if tool == "PMD" and "Checkstyle" in existing_messages:
        existing_messages.pop("Checkstyle")

    existing_messages[tool] = message

    if file_path not in POSTED_INLINE and line_num in path_in_diff:
        final_message = message
        if len(existing_messages) > 1:
            final_message += (
                "\n\n**Note**: For more comments, see the *Static Analysis Results* section below "
                f"for `{file_path}`."
            )
        payload = {
            "body": final_message,
            "commit_id": COMMIT_SHA,
            "path": file_path,
            "line": line_num,
            "position": 1,
        }
        print("Posting inline comment:\n" + json.dumps(payload, indent=2))
        response = requests.post(PR_REVIEW_COMMENTS_API, headers=HEADERS, json=payload)
        if response.status_code == 201:
            POSTED_INLINE.add(file_path)
        else:
            print(f"Inline comment failed: {response.status_code}\n{response.text}")

def post_general_comments():
    for file_path, line_msgs in GENERAL_COMMENTS.items():
        comment_body = f"### Static Analysis Results for `{file_path}`\n"
        for line_num, tool_msgs in sorted(line_msgs.items()):
            for msg in tool_msgs.values():
                comment_body += f"- Line {line_num}: {msg}\n"
        payload = {"body": comment_body}
        print(f"📋 General PR comment:\n{json.dumps(payload, indent=2)}")
        r = requests.post(PR_GENERAL_COMMENTS_API, headers=HEADERS, json=payload)
        if r.status_code != 201:
            print(r.text)

def parse_checkstyle(path):
    if not os.path.exists(path):
        print(f"⚠️ Checkstyle report not found: {path}")
        return
    tree = ET.parse(path)
    root = tree.getroot()
    for f in root.findall("file"):
        file_path = f.get("name")
        file_path = file_path[file_path.find("src/"):] if "src/" in file_path else file_path
        for err in f.findall("error"):
            line = err.get("line")
            severity = err.get("severity", "info").title()
            source = err.get("source")
            url = get_checkstyle_url(source)
            category = "unknown"
            parts = source.split(".") if source else []
            if "checks" in parts:
                idx = parts.index("checks")
                if idx + 1 < len(parts): category = parts[idx + 1].title()
            msg = f"[Checkstyle -> {category} -> {severity}] {err.get('message')} ([Reference]({url}))"
            post_inline_comment(file_path, line, msg, tool="Checkstyle")

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
        for v in violations:
            line = v.get("beginline")
            priority = v.get("priority", "3")
            severity = get_pmd_severity(priority).title()
            ruleset = v.get("ruleset", "unknown").title()
            url = v.get("externalInfoUrl", "")
            msg_text = v.text.strip()
            msg = f"[PMD -> {ruleset} -> {severity}] {msg_text} ([Reference]({url}))" if url else f"[PMD:{severity}][{ruleset}] {msg_text}"
            post_inline_comment(file_path, line, msg, tool="PMD")

# --- Run Everything ---
parse_checkstyle("build/reports/checkstyle/main.xml")
parse_pmd("build/reports/pmd/main.xml")
post_general_comments()
