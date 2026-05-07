from flask import Flask, render_template, request, jsonify
from src.enricher import enrich_ioc
from src.mitre_mapper import map_to_mitre

app = Flask(__name__)


@app.route("/")
def index():
    """Serves the main dashboard page."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """
    API endpoint — receives an IOC from the browser,
    runs the full pipeline, returns results as JSON.
    """
    data = request.get_json()
    ioc = data.get("ioc", "").strip()

    if not ioc:
        return jsonify({"error": "No IOC provided"}), 400

    try:
        # Run the full pipeline
        enrichment = enrich_ioc(ioc)
        mitre = map_to_mitre(enrichment)

        # Package everything for the frontend
        return jsonify({
            "ioc": ioc,
            "ioc_type": enrichment.get("ioc_type", "unknown"),
            "virustotal": enrichment.get("virustotal", {}),
            "shodan": enrichment.get("shodan", {}),
            "mitre": mitre
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)