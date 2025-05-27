import os
import xml.etree.ElementTree as ET
import requests

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
COMMIT_SHA = os.getenv("COMMIT_SHA")
REPO = os.getenv("REPO")

HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}
BASE_API = f"https://api.github.com/repos/{REPO}/commits/{COMMIT_SHA}/comments"

def post_comment(file_path, line, message):
    payload = {
        "body": message,
        "path": file_path,
        "line": int(line),
        "position": 1  # Dummy; GitHub uses it for PRs but ignores for direct commit comments
    }
    response = requests.post(BASE_API, headers=HEADERS, json=payload)
    print(f"Posted: {response.status_code} - {message}")

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
            message = f"[Checkstyle] {error.get('message')}"
            post_comment(file_path, line, message)

def parse_pmd(xml_path):
    if not os.path.exists(xml_path):
        print(f"PMD file not found: {xml_path}")
        return
    tree = ET.parse(xml_path)
    root = tree.getroot()
    for file_elem in root.findall("file"):
        file_path = file_elem.get("name")
        file_path = file_path[file_path.find("src/"):] if "src/" in file_path else file_path
        for violation in file_elem.findall("violation"):
            line = violation.get("beginline")
            message = f"[PMD] {violation.text.strip()}"
            post_comment(file_path, line, message)

# Paths to reports
parse_checkstyle("build/reports/checkstyle/main.xml")
parse_pmd("build/reports/pmd/main.xml")
