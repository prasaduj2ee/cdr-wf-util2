import os
import xml.etree.ElementTree as ET
import requests
import json
from collections import defaultdict

# --- Config from environment ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
COMMIT_SHA = os.getenv("COMMIT_SHA")
REPO = os.getenv("REPO")

HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

BASE_API = f"https://api.github.com/repos/{REPO}/commits/{COMMIT_SHA}/comments"

# --- Fetch commit diff to determine changed lines ---
def get_commit_diff_lines():
    diff_url = f"https://api.github.com/repos/{REPO}/commits/{COMMIT_SHA}"
    response = requests.get(diff_url, headers=HEADERS)
    if response.status_code != 200:
        print(f"Failed to fetch commit diff: {response.status_code}")
        return {}

    files_changed = response.json().get("files", [])
    diff_map = {}

    for f in files_changed:
        path = f["filename"]
        patch = f.get("patch", "")
        changed_lines = set()
        old_line = None
        new_line = None
        for line in patch.splitlines():
            if line.startswith("@@"):
                try:
                    new_info = line.split("@@")[1].split("+")[1].split(" ")[0]
                    new_start = int(new_info.split(",")[0])
                    new_line = new_start - 1
                except:
                    continue
            elif line.startswith("+") and not line.startswith("+++"):
                new_line += 1
                changed_lines.add(new_line)
            elif not line.startswith("-"):
                new_line += 1
        diff_map[path] = changed_lines
    return diff_map

DIFF_LINES = get_commit_diff_lines()
GENERAL_COMMENTS = defaultdict(list)  # file_path -> list of messages

# --- Severity mapping for PMD ---
def get_pmd_severity(priority):
    try:
        p = int(priority)
    except:
        return "Unknown"

    return {
        1: "High",
        2: "High",
        3: "Medium",
        4: "Low",
        5: "Info"
    }.get(p, "Unknown")

# --- Derive Checkstyle rule doc URL ---
def get_checkstyle_url(source: str) -> str:
    if not source:
        return ""
    parts = source.split(".")
    if "checks" in parts:
        idx = parts.index("checks")
        if idx + 1 < len(parts):
            category = parts[idx + 1]
            rule = parts[-1].replace("Check", "")
            return f"https://checkstyle.sourceforge.io/config_{category}.html#{rule}"
    return "https://checkstyle.sourceforge.io/checks.html"

# --- Post comment ---
def post_comment(file_path, line, message):
    file_path = file_path.strip()
    line_num = int(line) if line else None
    path_in_diff = DIFF_LINES.get(file_path, set())

    if line_num and line_num in path_in_diff:
        # Inline comment
        payload = {
            "body": message,
            "path": file_path,
            "line": line_num,
            "position": 1  # Required but ignored for commit comments
        }
        print("Posting inline comment:\n" + json.dumps(payload, indent=2))
        response = requests.post(BASE_API, headers=HEADERS, json=payload)
        print(f"Inline response {response.status_code}")
        if response.status_code != 201:
            print(response.text)
    else:
        # Queue general comment by file
        GENERAL_COMMENTS[file_path].append(f"Line {line}: {message}")

# --- Post grouped general comments ---
def post_general_comments():
    for file_path, messages in GENERAL_COMMENTS.items():
        comment_body = f"### Static Analysis Results for `{file_path}`\n"
        comment_body += "\n".join(f"- {msg}" for msg in messages)

        payload = {
            "body": comment_body
        }
        print("Posting grouped general comment:\n" + json.dumps(payload, indent=2))
        response = requests.post(BASE_API, headers=HEADERS, json=payload)
        print(f"General comment response {response.status_code}")
        if response.status_code != 201:
            print(response.text)

# --- Parse Checkstyle XML ---
def parse_checkstyle(xml_path):
    if not os.path.exists(xml_path):
        print(f"Checkstyle file not found: {xml_path}")
        return
    tree = ET.parse(xml_path)
    root = tree.getroot()
    for file_elem in root.findall("file"):
        file_path = file_elem.get("name")
        file_path = file_path[file_path.find("src/"):] if "src/" in file_path else file_path
        for error in file_elem.findall("error"):
            line = error.get("line")
            severity = error.get("severity", "info").title()
            source = error.get("source")
            url = get_checkstyle_url(source)

            # Extract category
            category = "unknown"
            parts = source.split(".") if source else []
            if "checks" in parts:
                idx = parts.index("checks")
                if idx + 1 < len(parts):
                    category = parts[idx + 1]
            category = category.title()
            message = f"[Checkstyle -> {category} -> {severity}] {error.get('message')} ([Reference]({url}))"
            post_comment(file_path, line, message)

# --- Parse PMD XML ---
def parse_pmd(xml_path):
    if not os.path.exists(xml_path):
        print(f"PMD file not found: {xml_path}")
        return
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Handle namespace
    namespace = ''
    if root.tag.startswith('{'):
        namespace = root.tag.split('}')[0].strip('{')
        ns = {'ns': namespace}
    else:
        ns = {}

    file_elements = root.findall("ns:file", ns) if ns else root.findall("file")
    for file_elem in file_elements:
        file_path = file_elem.get("name")
        file_path = file_path[file_path.find("src/"):] if "src/" in file_path else file_path

        violations = file_elem.findall("ns:violation", ns) if ns else file_elem.findall("violation")
        for violation in violations:
            line = violation.get("beginline")
            priority = violation.get("priority", "3")
            severity = get_pmd_severity(priority).title()
            ruleset = violation.get("ruleset", "unknown").title()
            url = violation.get("externalInfoUrl", "")
            msg_text = violation.text.strip()

            message = f"[PMD -> {ruleset} -> {severity}] {msg_text} ([Reference]({url}))" if url else f"[PMD:{severity}][{ruleset}] {msg_text}"
            post_comment(file_path, line, message)

# --- Main ---
parse_checkstyle("build/reports/checkstyle/main.xml")
parse_pmd("build/reports/pmd/main.xml")
post_general_comments()
