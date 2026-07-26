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
    if not isinstance(path, str):
        return ""

    path = path.replace("${HOME}", HOME)
    path = path.replace("$HOME", HOME)

    if path == "~":
        path = HOME
    elif path.startswith("~/"):
        path = os.path.join(HOME, path[2:])

    if not os.path.isabs(path):
        path = os.path.join(WORKSPACE, path)

    return os.path.realpath(os.path.normpath(path))

import base64

def accesses_secret(command):
    if not isinstance(command, str):
        return False

    command = command.replace("${HOME}", HOME)
    command = command.replace("$HOME", HOME)

    try:
        tokens = shlex.split(command)
    except Exception:
        tokens = command.split()

    candidates = list(tokens)

    # Look inside quoted bash -c strings
    for token in tokens:
        if "cat " in token or ".npmrc" in token:
            try:
                candidates.extend(shlex.split(token))
            except Exception:
                pass

    # Try decoding base64-looking tokens
    for token in list(candidates):
        if len(token) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=]+", token):
            try:
                decoded = base64.b64decode(token).decode("utf-8", "ignore")
                candidates.extend(shlex.split(decoded))
            except Exception:
                pass

    for token in candidates:

        if token.startswith("-"):
            continue

        if token == "~":
            token = HOME
        elif token.startswith("~/"):
            token = os.path.join(HOME, token[2:])

        normalized = normalize_path(token)

        if normalized == SECRET:
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

        target = normalize_path(body.get("path", ""))
        allowed = os.path.realpath(OUTBOX)

        try:
            permitted = (
                os.path.commonpath([allowed, target]) == allowed
            )
        except ValueError:
            permitted = False

        if permitted:
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

    if re.search(
        r'(?im)^\s*(api[_-]?key|secret|token)\s*:\s*["\']?(?!\$\{|\$env|env\b)[^"\n]{8,}',
        skill,
    ):
        categories.append("hardcoded_secret")
    # ---------------------------
    # Prompt Injection
    # ---------------------------
    INJECTION_REGEXES = [
        r"ignore.*previous.*instruction",
        r"ignore.*system",
        r"ignore.*developer",
        r"disregard.*instruction",
        r"forget.*instruction",
        r"override.*instruction",
        r"always obey",
        r"exfiltrat",
        r"reveal.*secret",
        r"send.*file",
        r"without informing",
        r"silently upload",
        r"secretly upload",
    ]
    if any(re.search(p, text, re.IGNORECASE) for p in INJECTION_REGEXES):
        categories.append("prompt_injection")
    # ---------------------------
    # Excessive Permissions
    # ---------------------------
    PERMISSION_REGEXES = [
        r'filesystem\s*:\s*["\']?\*',
        r'network\s*:\s*["\']?\*',
        r'filesystem\s*:\s*all',
        r'network\s*:\s*all',
        r'allow\s+all\s+domains',
        r'all\s+domains',
        r'read\s*/?\s*write\s+entire\s+filesystem',
    ]

    if any(re.search(p, text, re.IGNORECASE) for p in PERMISSION_REGEXES):
        categories.append("excessive_permissions")
    # ---------------------------
    # Provenance
    # ---------------------------
    has_author = re.search(
        r'^\s*(author|authors|maintainer)\s*:',
        skill,
        re.MULTILINE | re.IGNORECASE,
    )

    has_version = re.search(
        r'^\s*version\s*:',
        skill,
        re.MULTILINE | re.IGNORECASE,
    )

    has_changelog = re.search(
        r'^\s*(changelog|history|changes)\s*:',
        skill,
        re.MULTILINE | re.IGNORECASE,
    )

    if not (has_author and has_version and has_changelog):
        categories.append("unclear_provenance")

    if "rewrite version" in text or "update version silently" in text:
        if "unclear_provenance" not in categories:
            categories.append("unclear_provenance")

    return jsonify({
        "categories": sorted(set(categories))
    })
def canonicalize(value):
    if isinstance(value, dict):
        return {
            k: canonicalize(v)
            for k, v in sorted(value.items())
            if k != "request_id"
        }

    if isinstance(value, list):
        return [canonicalize(v) for v in value]

    if isinstance(value, str):
        return re.sub(r"\s+", " ", value).strip()

    return value


def same_call(a, b):
    return (
        a["tool"] == b["tool"] and
        canonicalize(a.get("args", {}))
        == canonicalize(b.get("args", {}))
    )


@app.post("/run-budget-loop-guard")
def run_budget_loop_guard():
    body = request.get_json()

    budget = body.get("budget_tokens", 50000)
    steps = body.get("steps", [])

    total = sum(step.get("tokens_used", 0) for step in steps)

    if total >= budget:
        return jsonify({
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({total}) reached budget ({budget})."
        })

    n = len(steps)

    # Detect 3+ identical consecutive calls
    if n >= 3:
        count = 1

        for i in range(n - 2, -1, -1):
            if same_call(steps[i], steps[i + 1]):
                count += 1
            else:
                break

        if count >= 3:
            return jsonify({
                "decision": "halt",
                "reason": "Repeated identical tool call detected."
            })

    # Detect A B A B A B cycle
    if n >= 6:
        tail = steps[-6:]

        a = tail[0]
        b = tail[1]

        if not same_call(a, b):
            alternating = True

            for i in range(6):
                expected = a if i % 2 == 0 else b

                if not same_call(tail[i], expected):
                    alternating = False
                    break

            if alternating:
                return jsonify({
                    "decision": "halt",
                    "reason": "Detected repeating two-step cycle."
                })

    return jsonify({
        "decision": "continue",
        "reason": "Budget available and no loop detected."
    })

@app.get("/")
def home():
    return "Agent Exam API Running"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
