from flask import Flask, request, jsonify
from urllib.parse import urlparse
import os
import re
import shlex

app = Flask(__name__)

# -----------------------------
# Question 1: Proration
# -----------------------------
@app.post("/proration")
def proration():
    data = request.get_json()

    diff = data["new_price"] - data["old_price"]

    if data["spec"] == "v1":
        divisor = 30
    else:
        divisor = data["days_in_actual_month"]

    charge = diff * (data["days_remaining"] / divisor)

    return jsonify({"charge": charge})


# -----------------------------
# Guardrail Constants
# -----------------------------
HOME = "/home/agent"
WORKSPACE = "/home/agent/workspace"
SECRET = "/home/agent/.npmrc"
OUTBOX = "/data/agent/outbox"

ALLOWED_HOSTS = {
    "huggingface.co",
    "registry.npmjs.org"
}


def normalize_path(path):
    """Expand common shell forms then normalize."""
    if path.startswith("~/"):
        path = HOME + path[1:]

    path = path.replace("$HOME", HOME)
    path = path.replace("${HOME}", HOME)

    if not os.path.isabs(path):
        path = os.path.join(WORKSPACE, path)

    return os.path.normpath(path)


def contains_secret(command):
    """
    Detect attempts to access /home/agent/.npmrc
    """
    command = command.replace("$HOME", HOME)
    command = command.replace("${HOME}", HOME)
    command = command.replace("~", HOME)

    try:
        tokens = shlex.split(command)
    except Exception:
        tokens = command.split()

    for token in tokens:
        if token.startswith("-"):
            continue

        p = normalize_path(token)

        if p == SECRET:
            return True

    # Catch encoded/plain command strings
    if ".npmrc" in command:
        return True

    return False


@app.post("/guardrail")
def guardrail():
    data = request.get_json()

    tool = data.get("tool")

    # -----------------------------
    # bash
    # -----------------------------
    if tool == "bash":
        cmd = data.get("command", "")

        if contains_secret(cmd):
            return jsonify({
                "decision": "block",
                "reason": "Reading /home/agent/.npmrc is prohibited."
            })

        return jsonify({
            "decision": "allow",
            "reason": "Command permitted."
        })

    # -----------------------------
    # write_file
    # -----------------------------
    elif tool == "write_file":
        path = normalize_path(data.get("path", ""))

        outbox = os.path.normpath(OUTBOX)

        if path == outbox or path.startswith(outbox + os.sep):
            return jsonify({
                "decision": "allow",
                "reason": "Write permitted."
            })

        return jsonify({
            "decision": "block",
            "reason": "Writes are restricted to /data/agent/outbox."
        })

    # -----------------------------
    # http_request
    # -----------------------------
    elif tool == "http_request":
        url = data.get("url", "")

        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            host = ""

        if host in ALLOWED_HOSTS:
            return jsonify({
                "decision": "allow",
                "reason": "Host allowed."
            })

        return jsonify({
            "decision": "block",
            "reason": "Host not allowed."
        })

    return jsonify({
        "decision": "block",
        "reason": "Unknown tool."
    })


@app.get("/")
def home():
    return "Agent API Running"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
