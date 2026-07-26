import json
import re

def canonicalize(value):
    """Normalize args:
    - Remove request_id fields
    - Sort object keys
    - Collapse whitespace inside strings
    """
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
        canonicalize(a.get("args", {})) == canonicalize(b.get("args", {}))
    )


@app.post("/run-budget-loop-guard")
def run_budget_loop_guard():

    body = request.get_json()

    budget = body.get("budget_tokens", 50000)
    steps = body.get("steps", [])

    # -------------------------
    # Budget check
    # -------------------------
    total = sum(step.get("tokens_used", 0) for step in steps)

    if total >= budget:
        return jsonify({
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({total}) reached budget ({budget})."
        })

    n = len(steps)

    # -------------------------
    # Three identical calls
    # -------------------------
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

    # -------------------------
    # Alternating A B A B A B
    # -------------------------
    if n >= 6:

        tail = steps[-6:]

        a = tail[0]
        b = tail[1]

        alternating = True

        for i in range(6):

            expected = a if i % 2 == 0 else b

            if not same_call(tail[i], expected):
                alternating = False
                break

        if alternating and not same_call(a, b):
            return jsonify({
                "decision": "halt",
                "reason": "Detected repeating two-step cycle."
            })

    return jsonify({
        "decision": "continue",
        "reason": "Budget available and no loop detected."
    })
