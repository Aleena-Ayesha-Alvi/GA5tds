from flask import Flask, request, jsonify

app = Flask(__name__)

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

@app.get("/")
def home():
    return "Proration API is running!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)