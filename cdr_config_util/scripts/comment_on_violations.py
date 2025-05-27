import os
import xml.etree.ElementTree as ET
import requests
import json
from collections import defaultdict

# --- Config from environment ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO = os.getenv("REPO")
PR_NUMBER = os.getenv("PR_NUMBER")

HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}

PR_COMMENT_API = f"https://api.github.com/repos/{REPO}/issues/{PR_NUMBER}/comments"
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

# --- Queue comment for later posting ---
def post_comment(file_path, line, message):
    file_path = file_path.strip()
    GENERAL_COMMENTS[file_path].append(f"Line {line}: {message}")

# --- Post grouped general PR comment ---
def post_general_comments():
    if not GENERAL_COMMENTS:
        print("✅ No violations to report.")
        return

    body = "### 🛡️ Static Analysis Report\n"
    for file_path, messages in GENERAL_COMMENTS.items():
        body += f"\n<details><summary><code>{file_path}</code></summary>\n\n"
        body += "\n".join(f"- {msg}" for msg in messages)
        body += "\n</details>\n"

    payload = { "body": body }

    print("📬 Posting PR comment...")
    response = requests.post(PR_COMMENT_API, headers=HEADERS, json=payload)
    print(f"Comment response {response.status_code}")
    if response.status_code != 201:
        print(response.text)
    else:
        print("✅ PR comment posted successfully.")

# --- Parse Checkstyle XML ---
def parse_checkstyle(xml_path):
    if not os.path.exists(xml_path):
        print(f"⚠️ Checkstyle report not found: {xml_path}")
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

            category = "Unknown"
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
        print(f"⚠️ PMD report not found: {xml_path}")
        return
    tree = ET.parse(xml_path)
    root = tree.getroot()

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
            ruleset = violation.get("ruleset", "Unknown").title()
            url = violation.get("externalInfoUrl", "")
            msg_text = violation.text.strip()

            if url:
                message = f"[PMD -> {ruleset} -> {severity}] {msg_text} ([Reference]({url}))"
            else:
                message = f"[PMD -> {ruleset} -> {severity}] {msg_text}"
            post_comment(file_path, line, message)

# --- Main ---
parse_checkstyle("build/reports/checkstyle/main.xml")
parse_pmd("build/reports/pmd/main.xml")
post_general_comments()
