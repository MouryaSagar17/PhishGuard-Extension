"""
PhishGuard V2 - combined URL + advanced features extraction.

Maintains backward compatibility with V1 while adding:
  - Domain metadata (age, registrar, WHOIS)
  - DNS and SSL certificate analysis
  - HTML content features
  - Redirect chain analysis
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any
from urllib.parse import urlparse

import numpy as np

from .advanced_features import AdvancedFeatureExtractor

# URL-based suspicious tokens (from V1)
_SUSPICIOUS_TOKENS = frozenset({
    "verify", "verification", "confirm", "confirm-verify", "suspended",
    "urgentaction", "unlock-account", "billing-alert", "security-alert",
    "unusual-activity",
})

_IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:]{0,4}$"
)

# V2 Feature names (extended from V1)
V1_FEATURES = [
    "url_len", "hostname_len", "path_len", "query_len", "scheme_https",
    "dots", "hyphens", "underscores", "at_count", "percent_count",
    "slashes_path", "use_ip", "digit_ratio_host", "suspicious_hits",
    "subdomains", "longest_path_token", "entropy_host", "punycode",
    "tld_suspicious",
]

V2_NEW_FEATURES = [
    # Domain metadata
    "domain_age_days", "domain_very_new", "domain_suspicious_age",
    # DNS
    "has_mx_records", "has_ns_records", "suspicious_dns",
    # SSL
    "has_valid_ssl", "ssl_self_signed", "ssl_cert_expires_soon",
    "ssl_brand_mismatch", "days_to_ssl_expiry",
    # Content
    "login_form_count", "password_field_count", "suspicious_iframe_count",
    "external_script_count", "form_action_mismatch", "obfuscated_js",
    "suspicious_onclick_count",
    # Redirects
    "estimated_redirects", "suspicious_redirect_chain",
]

FEATURE_NAMES = V1_FEATURES + V2_NEW_FEATURES


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


class URLFeatureExtractorV2:
    """
    PhishGuard V2 Feature Extractor.
    Combines V1 URL features with advanced domain + content analysis.
    """

    def __init__(self, enable_network_checks: bool = True):
        self.advanced_extractor = AdvancedFeatureExtractor(enable_network_checks=enable_network_checks)

    def transform_one(self, url: str, html_content: str = "", form_domain: str = "") -> np.ndarray:
        """
        Extract all features for a single URL.
        
        Args:
            url: Full URL string
            html_content: Optional HTML content for multi-modal analysis
            form_domain: Optional domain where forms submit to
        
        Returns:
            Feature vector as np.ndarray
        """
        features_dict = self._extract_all_features(url, html_content, form_domain)
        return np.array([features_dict[name] for name in FEATURE_NAMES], dtype=np.float64)

    def transform_many(self, urls: list[str], n_jobs: int = -1) -> np.ndarray:
        """
        Extract features for multiple URLs (URL only, no HTML).
        Uses parallel processing for large datasets.
        """
        if not urls:
            return np.empty((0, len(FEATURE_NAMES)))
        
        if len(urls) < 100:
            return np.vstack([self.transform_one(u) for u in urls])
        
        from joblib import Parallel, delayed

        def _batch(batch: list[str]) -> np.ndarray:
            return np.vstack([self.transform_one(u) for u in batch])

        batch_size = max(100, len(urls) // 32)
        batches = [urls[i : i + batch_size] for i in range(0, len(urls), batch_size)]
        parts = Parallel(n_jobs=n_jobs)(delayed(_batch)(b) for b in batches)
        return np.vstack(parts)

    def _extract_all_features(self, url: str, html_content: str = "", form_domain: str = "") -> dict[str, float]:
        """
        Extract V1 + V2 features.
        Falls back gracefully if advanced features fail.
        """
        # V1 features (always extracted)
        v1_features = self._extract_url_features(url)
        
        # V2 features (with fallback)
        v2_features = {}
        try:
            v2_features.update(self.advanced_extractor.extract_domain_features(url))
            if html_content:
                v2_features.update(self.advanced_extractor.extract_content_features(html_content, form_domain))
            else:
                # Placeholder content features if no HTML provided
                for fname in [
                    "login_form_count", "password_field_count", "suspicious_iframe_count",
                    "external_script_count", "form_action_mismatch", "obfuscated_js",
                    "suspicious_onclick_count"
                ]:
                    v2_features[fname] = 0.0
            v2_features.update(self.advanced_extractor.extract_redirect_features(url))
        except Exception as e:
            # Fallback: zero out V2 features if extraction fails
            print(f"Warning: V2 feature extraction failed for {url}: {e}")
            for fname in V2_NEW_FEATURES:
                v2_features[fname] = 0.0
        
        # Combine all
        combined = {**v1_features, **v2_features}
        return combined

    def _extract_url_features(self, url: str) -> dict[str, float]:
        """Extract V1 URL-only features."""
        raw = (url or "").strip()
        if not raw:
            return {name: 0.0 for name in V1_FEATURES}

        if "://" not in raw:
            raw = "http://" + raw

        try:
            parsed = urlparse(raw)
        except Exception:
            parsed = urlparse("http://invalid/")

        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""

        scheme_https = 1.0 if parsed.scheme == "https" else 0.0
        port = parsed.port
        non_standard_port = 0.0
        if port is not None and port not in (80, 443):
            non_standard_port = 1.0

        hostname_len = float(len(host))
        path_len = float(len(path))
        query_len = float(len(query))
        url_len = float(len(raw))

        dots = host.count(".")
        hyphens = host.count("-")
        underscores = (host + path).count("_")
        at_count = raw.count("@")
        percent_count = raw.count("%")
        slashes_path = path.count("/")

        use_ip = 1.0 if host and _IP_RE.match(host) else 0.0

        host_digits = sum(1 for c in host if c.isdigit())
        digit_ratio_host = host_digits / max(len(host), 1)

        blob = f"{host} {path} {query}".lower()
        tokens = re.split(r"[^a-z0-9]+", blob)
        suspicious_hits = sum(1 for t in tokens if t in _SUSPICIOUS_TOKENS)

        subdomains = max(dots, 0)
        longest_path_token = 0.0
        for t in path.split("/"):
            if len(t) > longest_path_token:
                longest_path_token = float(len(t))

        entropy_host = _shannon_entropy(host)

        punycode = 1.0 if "xn--" in host else 0.0

        tld_suspicious = 0.0
        if host and "." in host:
            tld = host.rsplit(".", 1)[-1]
            if tld in {"tk", "ml", "ga", "cf", "gq"}:
                tld_suspicious = 1.0

        return {
            "url_len": url_len,
            "hostname_len": hostname_len,
            "path_len": path_len,
            "query_len": query_len,
            "scheme_https": scheme_https,
            "dots": float(dots),
            "hyphens": float(hyphens),
            "underscores": float(underscores),
            "at_count": float(at_count),
            "percent_count": float(percent_count),
            "slashes_path": float(slashes_path),
            "use_ip": use_ip,
            "digit_ratio_host": digit_ratio_host,
            "suspicious_hits": float(suspicious_hits),
            "subdomains": float(subdomains),
            "longest_path_token": longest_path_token,
            "entropy_host": entropy_host,
            "punycode": punycode,
            "tld_suspicious": tld_suspicious,
        }


# Backward compatibility export
bundle_meta = {
    "version": "2.0.0",
    "feature_count": len(FEATURE_NAMES),
    "features": FEATURE_NAMES,
    "v1_features": V1_FEATURES,
    "v2_new_features": V2_NEW_FEATURES,
}
