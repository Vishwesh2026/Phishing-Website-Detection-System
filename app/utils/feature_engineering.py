"""
app/utils/feature_engineering.py
─────────────────────────────────────────────────────────────
Advanced URL feature extraction pipeline.

• URLFeatureExtractor  — custom sklearn transformer (11 structural features)
• build_pipeline()     — ColumnTransformer combining:
    1. Word-level TF-IDF on raw URL text
    2. Char-level n-gram TF-IDF (trigrams → 5-grams)
    3. Structural numerical features
"""

from __future__ import annotations

import math
import re
from typing import Iterable
from urllib.parse import urlparse

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline


# ── Constants ─────────────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS: frozenset[str] = frozenset([
    "login", "secure", "account", "update", "banking", "verify",
    "ebayisapi", "webscr", "signin", "confirm", "paypal", "password",
    "credential", "validation", "auth", "token",
])

SPECIAL_CHARS: str = r"/?=&%#@!$"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (bits per character)."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _is_ip_address(netloc: str) -> int:
    """Return 1 if netloc is an IPv4 address (without port), else 0."""
    host = netloc.split(":")[0]
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(pattern, host):
        parts = host.split(".")
        return int(all(0 <= int(p) <= 255 for p in parts))
    return 0


def _clean_url_for_text(url: str) -> str:
    """Strip scheme/www for TF-IDF feature extraction (matches original training logic)."""
    return re.sub(r"^https?://(www\.)?", "", url)


# ── Custom Transformer ────────────────────────────────────────────────────────

class URLFeatureExtractor(BaseEstimator, TransformerMixin):
    """
    Extracts 11 numerical structural features from a raw URL string.

    Used inside an sklearn Pipeline as a custom transformer so that both
    training and inference use the exact same feature extraction logic
    without any state to fit (fit() is a no-op).
    """

    FEATURE_NAMES: list[str] = [
        "url_length",
        "dot_count",
        "hyphen_count",
        "digit_count",
        "subdomain_count",
        "has_ip_address",
        "has_at_symbol",
        "has_suspicious_keyword",
        "uses_https",
        "domain_entropy",
        "special_char_ratio",
    ]

    def fit(self, X: Iterable[str], y=None) -> "URLFeatureExtractor":  # noqa: D102
        return self  # stateless

    def transform(self, X: Iterable[str]) -> np.ndarray:  # noqa: D102
        return np.array([self._extract(url) for url in X], dtype=np.float64)

    # ── Per-URL extraction ────────────────────────────────────────────────────

    def _extract(self, url: str) -> list[float]:
        parsed = urlparse(url)
        netloc: str = parsed.netloc or ""
        path: str = parsed.path or ""
        domain: str = netloc.split(":")[0]          # strip port
        full: str = netloc + path                    # netloc + path for special char count

        # 1. URL length
        url_length = float(len(url))

        # 2. Dot count (indicates subdomain depth / obfuscation)
        dot_count = float(url.count("."))

        # 3. Hyphen count (hyphens are rare in legit domains)
        hyphen_count = float(url.count("-"))

        # 4. Digit count
        digit_count = float(sum(c.isdigit() for c in url))

        # 5. Subdomain count (number of domain labels minus 2 for domain + TLD)
        labels = domain.split(".")
        subdomain_count = float(max(0, len(labels) - 2))

        # 6. IP in netloc
        has_ip = float(_is_ip_address(netloc))

        # 7. @ symbol (often used to obfuscate real domain)
        has_at = float("@" in url)

        # 8. Suspicious keyword in URL
        url_lower = url.lower()
        has_kw = float(any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS))

        # 9. HTTPS usage
        uses_https = float(parsed.scheme == "https")

        # 10. Shannon entropy of domain (high entropy → random-looking)
        domain_entropy = _shannon_entropy(domain)

        # 11. Special character ratio relative to full URL length
        special_count = sum(1 for c in full if c in SPECIAL_CHARS)
        special_ratio = special_count / max(len(full), 1)

        return [
            url_length,
            dot_count,
            hyphen_count,
            digit_count,
            subdomain_count,
            has_ip,
            has_at,
            has_kw,
            uses_https,
            domain_entropy,
            special_ratio,
        ]


# ── Pipeline Factory ──────────────────────────────────────────────────────────

def build_pipeline(classifier) -> Pipeline:
    """
    Builds a complete sklearn Pipeline combining:
      - Word-level TF-IDF on cleaned URL text
      - Character n-gram TF-IDF (trigrams → 5-grams)
      - URLFeatureExtractor (11 structural features)

    The final step is the provided classifier.

    Args:
        classifier: Any sklearn-compatible estimator (e.g. RandomForest, XGBoost).

    Returns:
        sklearn.pipeline.Pipeline ready for fit() and predict().
    """

    # ── Text features from cleaned URL (word TF-IDF) ─────────────────────────
    word_tfidf = TfidfVectorizer(
        analyzer="word",
        tokenizer=lambda url: re.split(r"[\W_]+", url.lower()),
        token_pattern=None,
        max_features=30_000,
        ngram_range=(1, 2),
        sublinear_tf=True,
    )

    # ── Character n-gram TF-IDF ───────────────────────────────────────────────
    char_tfidf = TfidfVectorizer(
        analyzer="char_wb",
        max_features=20_000,
        ngram_range=(3, 5),
        sublinear_tf=True,
    )

    # ── Combine all text features ─────────────────────────────────────────────
    text_features = FeatureUnion([
        ("word_tfidf", word_tfidf),
        ("char_tfidf", char_tfidf),
    ])

    # ── Structural numerical features ─────────────────────────────────────────
    structural_features = URLFeatureExtractor()

    # ── Full transformer combining text + structural ──────────────────────────
    preprocessor = ColumnTransformer(
        transformers=[
            ("text", text_features, 0),           # column 0 = raw URL string
            ("structural", structural_features, 0),
        ],
        remainder="drop",
        sparse_threshold=0.3,
    )

    return Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", classifier),
    ])
