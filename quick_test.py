#!/usr/bin/env python3
"""
quick_test.py
-------------
CLI helper to score URLs using the trained model (with graceful fallbacks).
"""

import argparse
import json
import math
import os
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import threading

import joblib
import pandas as pd

from feature_extractor import FeatureExtractor

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL = os.path.join(HERE, "phishing_model.pkl")
FEATS = os.path.join(HERE, "feature_columns.pkl")
DEFAULT_THRESHOLD = 0.5
DEFAULT_DOMAIN_MARGIN = 0.03
DEFAULT_DOMAIN_BAND = 0.2
DEFAULT_DOMAIN_DELTA = 0.12


def read_first_col_csv(path):
    df = pd.read_csv(path, header=0)
    if "url" in df.columns:
        return df["url"].astype(str).tolist()
    return df[df.columns[0]].astype(str).tolist()


def normalize_variants(u):
    u = str(u).strip()
    if not u:
        return "", ""
    if "://" not in u and "/" in u:
        u = "http://" + u
    parsed = urllib.parse.urlparse(u, scheme="http")
    host = parsed.netloc.lower()
    path = parsed.path.rstrip("/")
    full = f"{parsed.scheme}://{host}{path}" if path else f"{parsed.scheme}://{host}"
    return full, host


def heuristic_prob(url):
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    host = parsed.netloc.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    score = 0.0
    if len(url) > 75:
        score += 1.0
    elif len(url) > 50:
        score += 0.5
    if parsed.scheme != "https":
        score += 0.8
    if "@" in url:
        score += 1.5
    shorteners = {"t.co", "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly"}
    if any(h in host for h in shorteners):
        score += 1.2
    try:
        import ipaddress

        if host and ipaddress.ip_address(host.split(":")[0]):
            score += 1.5
    except Exception:
        pass
    if host.count(".") >= 3:
        score += 0.6
    if "-" in host.split(".")[-2] if len(host.split(".")) > 1 else False:
        score += 0.4
    if len(query) > 30:
        score += 0.5
    if len(path) > 100:
        score += 0.6
    if "//" in path[1:]:
        score += 0.4
    tld = host.split(".")[-1] if host else ""
    if tld in {"xyz", "top", "zip", "review", "country", "gq", "cf"}:
        score += 0.6
    return 1 - 1 / (1 + math.exp(score - 1.0))


def load_model_safe():
    try:
        model = joblib.load(MODEL)
        feature_columns = joblib.load(FEATS)
        return model, feature_columns, None
    except Exception as exc:
        return None, None, str(exc)


def is_whitelisted_domain(domain):
    """Check if domain is in the whitelist"""
    whitelist = {
        "kaggle.com",
        "google.com",
        "youtube.com",
        "facebook.com",
        "wikipedia.org",
        "twitter.com",
        "instagram.com",
        "linkedin.com",
        "microsoft.com",
        "apple.com",
        "amazon.com",
        "github.com",
        "stackoverflow.com",
        "reddit.com",
        "netflix.com",
        "microsoftonline.com",
        "office.com",
        "adobe.com",
        "paypal.com",
        "ebay.com",
        "walmart.com",
        "cnn.com",
        "bbc.com",
        "nytimes.com",
        "washingtonpost.com",
    }

    domain_parts = domain.lower().split(".")
    for i in range(len(domain_parts)):
        test_domain = ".".join(domain_parts[i:])
        if test_domain in whitelist:
            return True
    return False


def evaluate_with_model(model, feature_columns, extractor, url):
    feats = extractor.extract(url)
    frame = pd.DataFrame([feats]).reindex(columns=feature_columns, fill_value=0)
    probability = float(model.predict_proba(frame)[:, 1][0])
    return probability


def get_domain_probability(model_bundle, extractor, base_url, host):
    cache = model_bundle.setdefault("domain_cache", {})
    lock = model_bundle.setdefault("cache_lock", threading.Lock())
    host_key = host.lower()
    with lock:
        cached = cache.get(host_key)
    if cached is not None:
        return cached
    model = model_bundle["model"]
    features = model_bundle["feature_columns"]
    probability = None
    if model is not None:
        try:
            probability = evaluate_with_model(model, features, extractor, base_url)
        except Exception:
            probability = None
    with lock:
        cache[host_key] = probability
    return probability


def classify_url(raw_url, extractor, model_bundle, threshold, consistency_opts):
    full, host = normalize_variants(raw_url)
    target_url = full or raw_url
    result = {
        "input": raw_url,
        "normalized": target_url,
        "host": host,
        "label": "UNKNOWN",
        "probability": None,
        "method": "parser",
        "reason": "",
        "warning": "",
    }

    if not host:
        result["reason"] = "could_not_parse_host"
        return result

    if is_whitelisted_domain(host):
        result.update(
            label="LEGIT",
            method="whitelist",
            reason="domain is whitelisted",
            probability=0.0,
        )
        return result

    if extractor._is_phishing_domain(host):
        result.update(
            label="PHISH",
            method="blacklist",
            reason="domain is blacklisted",
            probability=1.0,
        )
        return result

    model = model_bundle["model"]
    feature_columns = model_bundle["feature_columns"]

    if model is not None:
        try:
            probability = evaluate_with_model(model, feature_columns, extractor, target_url)
            label = "PHISH" if probability >= threshold else "LEGIT"
            result.update(
                label=label,
                probability=probability,
                method="model",
                reason=f"threshold={threshold}",
            )

            if (
                consistency_opts["enabled"]
                and label == "PHISH"
                and host
                and probability <= threshold + consistency_opts["band"]
            ):
                parsed = urllib.parse.urlparse(target_url)
                scheme = parsed.scheme or "http"
                base_url = f"{scheme}://{host}/"
                domain_prob = get_domain_probability(model_bundle, extractor, base_url, host)
                if domain_prob is not None:
                    safe_margin = domain_prob <= max(threshold - consistency_opts["margin"], 0)
                    relative_close = (
                        domain_prob < threshold
                        and (probability - domain_prob) <= consistency_opts["delta"]
                    )
                    if safe_margin or relative_close:
                        result.update(
                            label="LEGIT",
                            method="model+domain_consistency",
                            reason=(
                                f"domain_prob={domain_prob:.3f} "
                                f"margin={consistency_opts['margin']} "
                                f"delta={probability - domain_prob:.3f}"
                            ),
                            probability=probability,
                        )
            return result
        except Exception as exc:
            result["warning"] = f"model_error: {exc}"
    else:
        result["warning"] = f"model_not_loaded: {model_bundle['error'] or 'unknown'}"

    probability = heuristic_prob(target_url)
    label = "PHISH" if probability >= threshold else "LEGIT"
    result.update(
        label=label,
        probability=probability,
        method="heuristic",
        reason="heuristic_fallback",
    )
    return result


def emit_result(result, fmt, show_prob):
    payload = {
        "input": result["input"],
        "normalized": result["normalized"],
        "label": result["label"],
        "method": result["method"],
        "reason": result["reason"],
        "warning": result["warning"],
        "probability": result["probability"],
    }

    if fmt == "json":
        data = payload.copy()
        if not show_prob:
            data.pop("probability", None)
        print(json.dumps(data))
        return

    line = f"{payload['input']} --> {payload['label']} ({payload['method']})"
    if show_prob and payload["probability"] is not None:
        line += f"  prob={payload['probability']:.3f}"
    if payload["reason"]:
        line += f"  reason={payload['reason']}"
    if payload["warning"]:
        line += f"  warning={payload['warning']}"
    print(line)


def collect_urls(args):
    urls = []
    if args.file:
        file_path = args.file
        ext = os.path.splitext(file_path)[1].lower()
        if ext == ".txt":
            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                urls.extend([line.strip() for line in fh if line.strip()])
        elif ext == ".csv":
            urls.extend(read_first_col_csv(file_path))
        else:
            print(f"Unsupported file type: {ext}")
            sys.exit(1)

    urls.extend(args.urls or [])
    return urls


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("urls", nargs="*", help="URLs to test (or use --file)")
    ap.add_argument("--file", "-f", help="File (txt or csv) with URLs")
    ap.add_argument("--show-prob", action="store_true", help="Show probabilities.")
    ap.add_argument(
        "--threshold",
        type=float,
        default=DEFAULT_THRESHOLD,
        help=f"Probability threshold for PHISH classification (default: {DEFAULT_THRESHOLD})",
    )
    ap.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format.",
    )
    ap.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker threads for URL scoring (default: 1).",
    )
    ap.add_argument(
        "--domain-consistency-margin",
        type=float,
        default=DEFAULT_DOMAIN_MARGIN,
        help="Require the base domain probability to be below (threshold - margin) to override.",
    )
    ap.add_argument(
        "--domain-consistency-band",
        type=float,
        default=DEFAULT_DOMAIN_BAND,
        help="Allow override only if URL probability is within this band above the threshold.",
    )
    ap.add_argument(
        "--domain-consistency-delta",
        type=float,
        default=DEFAULT_DOMAIN_DELTA,
        help="Override if (url_prob - domain_prob) is within this delta while the domain is still below threshold.",
    )
    ap.add_argument(
        "--disable-domain-consistency",
        action="store_true",
        help="Disable domain-level consistency overrides.",
    )
    args = ap.parse_args()

    urls = collect_urls(args)
    if not urls:
        print("No URLs provided. Provide as arguments or with --file")
        sys.exit(1)
    if args.workers < 1:
        print("--workers must be >= 1")
        sys.exit(1)

    model, feature_columns, model_err = load_model_safe()
    model_bundle = {
        "model": model,
        "feature_columns": feature_columns or [],
        "error": model_err,
        "domain_cache": {},
        "cache_lock": threading.Lock(),
    }

    consistency_opts = {
        "enabled": not args.disable_domain_consistency,
        "margin": max(args.domain_consistency_margin, 0.0),
        "band": max(args.domain_consistency_band, 0.0),
        "delta": max(args.domain_consistency_delta, 0.0),
    }

    def classify_with_extractor(target_url, extractor=None):
        active_extractor = extractor or FeatureExtractor()
        return classify_url(
            target_url,
            active_extractor,
            model_bundle,
            args.threshold,
            consistency_opts,
        )

    if args.workers == 1:
        shared_extractor = FeatureExtractor()
        for url in urls:
            result = classify_with_extractor(url, shared_extractor)
            emit_result(result, args.format, args.show_prob)
    else:
        worker_count = min(args.workers, max(1, len(urls)))

        def worker(url):
            return classify_with_extractor(url)

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            for result in executor.map(worker, urls):
                emit_result(result, args.format, args.show_prob)

if __name__ == "__main__":
    main()
