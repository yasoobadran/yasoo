import unittest
from unittest.mock import patch

import quick_test


class StubExtractor:
    """Minimal extractor stub to satisfy quick_test.classify_url."""

    def _is_trusted_domain(self, domain):
        return False

    def _is_phishing_domain(self, value):
        return False

    def extract(self, url):
        return {}


def _make_model_bundle():
    return {"model": object(), "feature_columns": [], "error": None}


def _make_opts(enabled=True, margin=0.03, band=0.1, delta=0.12):
    return {"enabled": enabled, "margin": margin, "band": band, "delta": delta}


class DomainConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.extractor = StubExtractor()
        self.model_bundle = _make_model_bundle()

    def test_overrides_when_base_url_safe(self):
        def fake_eval(model, feature_columns, extractor, url):
            return 0.55 if "download" in url else 0.42

        with patch("quick_test.evaluate_with_model", side_effect=fake_eval):
            result = quick_test.classify_url(
                "https://moviesmod.plus/download-item",
                self.extractor,
                self.model_bundle,
                quick_test.DEFAULT_THRESHOLD,
                _make_opts(margin=0.03, band=0.2),
            )

        self.assertEqual(result["label"], "LEGIT")
        self.assertEqual(result["method"], "model+domain_consistency")

    def test_uses_delta_when_margin_not_met(self):
        def fake_eval(model, feature_columns, extractor, url):
            return 0.56 if "download" in url else 0.49

        with patch("quick_test.evaluate_with_model", side_effect=fake_eval):
            result = quick_test.classify_url(
                "https://moviesmod.plus/download-item",
                self.extractor,
                self.model_bundle,
                quick_test.DEFAULT_THRESHOLD,
                _make_opts(margin=0.03, band=0.2, ),
            )

        self.assertEqual(result["label"], "LEGIT")
        self.assertEqual(result["method"], "model+domain_consistency")

    def test_does_not_override_when_margin_and_delta_fail(self):
        def fake_eval(model, feature_columns, extractor, url):
            return 0.72 if "download" in url else 0.49

        with patch("quick_test.evaluate_with_model", side_effect=fake_eval):
            result = quick_test.classify_url(
                "https://moviesmod.plus/download-item",
                self.extractor,
                self.model_bundle,
                quick_test.DEFAULT_THRESHOLD,
                _make_opts(margin=0.03, band=0.2),
            )

        self.assertEqual(result["label"], "PHISH")
        self.assertEqual(result["method"], "model")


if __name__ == "__main__":
    unittest.main()
