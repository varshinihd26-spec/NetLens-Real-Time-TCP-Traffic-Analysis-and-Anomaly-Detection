from flask import Flask, render_template, jsonify
from sniffer import start_sniffer, get_dashboard_data

app = Flask(__name__)


start_sniffer()


@app.route("/")
def index():
    """Renders the main NetLens web dashboard interface."""
    return render_template("index.html")


@app.route("/api/data")
def api_data():
    """Real-time TCP packet data, statistics, and anomalies."""
    data = get_dashboard_data()
    return jsonify(data)


if __name__ == "__main__":
    print("Starting NetLens Web Dashboard on http://127.0.0.1:5000")
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
