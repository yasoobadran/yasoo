## Phishing Detection Toolkit

Core modules:

1. **feature_extractor.py** - extracts ~90 lexical/DNS/WHOIS/HTML features per URL (with caching/logging and graceful fallbacks).
2. **train_model.py** - builds a scikit-learn pipeline (imputer -> scaler -> RandomForest + RandomizedSearchCV) and saves `phishing_model.pkl`, `feature_columns.pkl`, and `training_report.txt`.
3. **quick_test.py** - CLI utility that scores URLs via the saved pipeline, with whitelist/blacklist shortcuts, heuristic fallback, domain-consistency smoothing, and batching.

### Environment

```
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### Training the Model

```
python train_model.py
```

Outputs:
- `phishing_model.pkl` - serialized pipeline (preprocess + classifier).
- `feature_columns.pkl` - ordered feature names required for inference.
- `training_report.txt` - JSON metrics (rows, feature count, accuracy, ROC-AUC, precision/recall/F1, best params).

### CLI Scoring (`quick_test.py`)

```
python quick_test.py https://example.com --show-prob
python quick_test.py --file urls.txt --format json
python quick_test.py --threshold 0.6 --disable-domain-consistency
```

Useful flags:
- `--show-prob` - print model probability (0-1).
- `--format {text,json}` - output style.
- `--threshold` - probability cut-off for PHISH.
- `--domain-consistency-*` - tune the smoothing logic when the base domain is legit but long sub-paths look suspicious.
- `--workers` - number of threads when scanning multiple URLs.

### Maintaining Domain Lists

```
python update_domain_lists.py --legit-source fresh_legit.txt
python update_domain_lists.py --phish-source https://example.com/latest_phish.csv
python update_domain_lists.py --legit-source legit.txt --phish-source phish.csv --dry-run
```

- Sources can be local files or HTTP(S) endpoints.
- Legit lists expect one domain per line.
- Phish lists can be CSV or newline text; the first column is consumed and deduped.

### REST API + Frontend

1. Install deps (once): `pip install -r requirements.txt`.
2. Launch the Flask service: `python api.py`.
3. Visit http://localhost:5000/ for the dashboard, or call the API directly.

Endpoints:
- `GET /health` - readiness + model metadata.
- `POST /api/analyze` - body `{ "url": "https://foo" }` or `{ "urls": ["..."] }`, response `{ "results": [ ... ] }` mirroring `quick_test.py`.

Environment knobs:
- `PHISHING_THRESHOLD`, `PHISHING_DOMAIN_MARGIN`, `PHISHING_DOMAIN_BAND`, `PHISHING_DOMAIN_DELTA` - same semantics as the CLI flags.
- `PHISHING_API_HOST`, `PHISHING_API_PORT`, `PHISHING_API_DEBUG` - Flask runtime settings.

`frontend/index.html` is a lightweight dashboard (dark theme + recent-history panel) that talks to `/api/analyze`. The previous marketing site is preserved as `frontend/legacy_index.html`.

### Tests

```
python -m unittest discover -s tests
```

Current tests assert the domain-consistency override logic; expand this suite as you extend the extractor, API, or CLI flows.
