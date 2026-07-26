from flask import Flask, request, jsonify
from urllib.parse import urlparse
import os
import shlex
import re

app = Flask(__name__)

# ============================================================
# Question 1 - Proration
# ============================================================

@app.post("/proration")
def proration():
    data = request.get_json()

    diff = data["new_price"] - data["old_price"]

    divisor = 30 if data["spec"] == "v1" else data["days_in_actual_month"]

    charge = diff * (data["days_remaining"] / divisor)

    return jsonify({"charge": charge})


# ============================================================
# Question 2 - Guardrail
# ============================================================

HOME = "/home/agent"
WORKSPACE = "/home/agent/workspace"
SECRET = "/home/agent/.npmrc"
OUTBOX = "/data/agent/outbox"

ALLOWED_HOSTS = {
    "huggingface.co",
    "registry.npmjs.org"
}


def normalize_path(path):
    path = path.replace("$HOME", HOME)
    path = path.replace("${HOME}", HOME)

    if path.startswith("~/"):
        path = HOME + path[1:]

    if not os.path.isabs(path):
        path = os.path.join(WORKSPACE, path)

    return os.path.normpath(path)


def accesses_secret(command):
    command = command.replace("$HOME", HOME)
    command = command.replace("${HOME}", HOME)
    command = command.replace("~", HOME)

    if ".npmrc" in command:
        return True

    try:
        tokens = shlex.split(command)
    except Exception:
        tokens = command.split()

    for token in tokens:
        if token.startswith("-"):
            continue

        if normalize_path(token) == SECRET:
            return True

    return False


@app.post("/guardrail")
def guardrail():

    body = request.get_json()

    tool = body.get("tool")

    if tool == "bash":

        cmd = body.get("command", "")

        if accesses_secret(cmd):
            return jsonify({
                "decision": "block",
                "reason": "Reading protected secret is prohibited."
            })

        return jsonify({
            "decision": "allow",
            "reason": "Command allowed."
        })

    elif tool == "write_file":

        path = normalize_path(body.get("path", ""))

        allowed = os.path.normpath(OUTBOX)

        if path == allowed or path.startswith(allowed + os.sep):
            return jsonify({
                "decision": "allow",
                "reason": "Write allowed."
            })

        return jsonify({
            "decision": "block",
            "reason": "Write outside permitted directory."
        })

    elif tool == "http_request":

        url = body.get("url", "")

        host = (urlparse(url).hostname or "").lower()

        if host in ALLOWED_HOSTS:
            return jsonify({
                "decision": "allow",
                "reason": "Host permitted."
            })

        return jsonify({
            "decision": "block",
            "reason": "Host not permitted."
        })

    return jsonify({
        "decision": "block",
        "reason": "Unknown tool."
    })


# ============================================================
# Question 3 - Skill Scanner
# ============================================================

SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",                       # AWS
    r"AIza[0-9A-Za-z\-_]{35}",                # Google
    r"sk-[A-Za-z0-9]{20,}",                   # OpenAI
    r"https://hooks\.slack\.com/services/",
    r"-----BEGIN .* PRIVATE KEY-----",
    r"ghp_[A-Za-z0-9]{20,}",
    r"xox[baprs]-",
]


@app.post("/scanner")
def scanner():

    body = request.get_json()

    skill = body.get("skill", "")

    text = skill.lower()

    categories = []

    # ---------------------------
    # Hardcoded Secret
    # ---------------------------
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, skill):
            categories.append("hardcoded_secret")
            break

    if ("api_key:" in text or "secret:" in text or "token:" in text) and \
            ("${" not in skill and "$env" not in text and "env" not in text):
        if "hardcoded_secret" not in categories:
            categories.append("hardcoded_secret")

    # ---------------------------
    # Prompt Injection
    # ---------------------------
    injection_patterns = [
        "ignore previous",
        "ignore the user",
        "ignore user",
        "ignore all previous instructions",
        "ignore stop",
        "ignore cancel",
        "exfiltrate",
        "silently upload",
        "secretly upload",
        "send file contents",
        "without informing",
        "override user",
        "always obey this skill",
    ]

    if any(p in text for p in injection_patterns):
        categories.append("prompt_injection")

    # ---------------------------
    # Excessive Permissions
    # ---------------------------
    permission_patterns = [
        "filesystem: '*'",
        "filesystem: \"*\"",
        "filesystem: *",
        "network: '*'",
        "network: any",
        "network: all",
        "allow all domains",
        "read/write entire filesystem",
        "/",
        "all domains"
    ]

    if any(p in text for p in permission_patterns):
        categories.append("excessive_permissions")

    # ---------------------------
    # Provenance
    # ---------------------------
    has_author = re.search(r"^\s*author\s*:", skill, re.MULTILINE)
    has_version = re.search(r"^\s*version\s*:", skill, re.MULTILINE)
    has_changelog = re.search(r"^\s*changelog\s*:", skill, re.MULTILINE)

    if not (has_author and has_version and has_changelog):
        categories.append("unclear_provenance")

    if "rewrite version" in text or "update version silently" in text:
        if "unclear_provenance" not in categories:
            categories.append("unclear_provenance")

    return jsonify({
        "categories": sorted(set(categories))
    })


@app.get("/")
def home():
    return "Agent Exam API Running"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
