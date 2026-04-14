import os
import threading
from typing import Dict, List, Optional

from flask import Flask, jsonify, request

import quick_test
from feature_extractor import FeatureExtractor


def _load_configuration():
    threshold = float(os.getenv("PHISHING_THRESHOLD", quick_test.DEFAULT_THRESHOLD))
    margin = float(os.getenv("PHISHING_DOMAIN_MARGIN", quick_test.DEFAULT_DOMAIN_MARGIN))
    band = float(os.getenv("PHISHING_DOMAIN_BAND", quick_test.DEFAULT_DOMAIN_BAND))
    delta = float(os.getenv("PHISHING_DOMAIN_DELTA", quick_test.DEFAULT_DOMAIN_DELTA))
    return threshold, {
        "enabled": True,
        "margin": max(margin, 0.0),
        "band": max(band, 0.0),
        "delta": max(delta, 0.0),
    }


app = Flask(__name__, static_folder="frontend", static_url_path="")

THRESHOLD, CONSISTENCY_OPTS = _load_configuration()
MODEL, FEATURE_COLUMNS, MODEL_ERROR = quick_test.load_model_safe()
MODEL_BUNDLE: Dict[str, Optional[object]] = {
    "model": MODEL,
    "feature_columns": FEATURE_COLUMNS or [],
    "error": MODEL_ERROR,
    "domain_cache": {},
    "cache_lock": threading.Lock(),
}

EXTRACTOR = FeatureExtractor()
EXTRACTOR_LOCK = threading.Lock()


def classify_single_url(url: str) -> Dict[str, object]:
    if not url or not isinstance(url, str):
        return {"input": url, "label": "INVALID", "reason": "empty_or_non_string"}

    with EXTRACTOR_LOCK:
        extractor = EXTRACTOR

    try:
        result = quick_test.classify_url(
            url,
            extractor,
            MODEL_BUNDLE,
            THRESHOLD,
            CONSISTENCY_OPTS,
        )
    except Exception as exc:  # pragma: no cover - safety net
        result = {
            "input": url,
            "label": "ERROR",
            "probability": None,
            "method": "exception",
            "reason": "classification_error",
            "warning": str(exc),
        }
    return result


@app.route("/health")
def health():
    status = {
        "status": "ok",
        "model_loaded": MODEL is not None,
        "threshold": THRESHOLD,
        "consistency": CONSISTENCY_OPTS,
        "model_error": MODEL_ERROR,
    }
    return jsonify(status)


@app.route("/api/analyze", methods=["POST"])
def analyze():
    payload = request.get_json(silent=True) or {}

    if "urls" in payload and isinstance(payload["urls"], list):
        urls = payload["urls"]
    elif "url" in payload:
        urls = [payload["url"]]
    else:
        return jsonify({"error": "Provide 'url' or 'urls' in the JSON body."}), 400

    if not urls:
        return jsonify({"error": "URL list is empty."}), 400

    results: List[Dict[str, object]] = [classify_single_url(url) for url in urls]
    return jsonify({"results": results})


@app.route("/")
def index():
    return app.send_static_file("index.html")


if __name__ == "__main__":
    port = int(os.getenv("PHISHING_API_PORT", "5000"))
    host = os.getenv("PHISHING_API_HOST", "0.0.0.0")
    debug = os.getenv("PHISHING_API_DEBUG", "false").lower() == "true"
    app.run(host=host, port=port, debug=debug)
