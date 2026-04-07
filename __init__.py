"""
PhishGuard V2 - Advanced phishing detection with ML and explainability

Features:
  - Multi-modal detection (URL + HTML content)
  - Advanced feature extraction (WHOIS, DNS, SSL)
  - Model comparison and hyperparameter tuning
  - SHAP-based explainability
  - Risk levels (safe, suspicious, phishing)
  - API caching and optimization
  - Comprehensive evaluation metrics

Version: 2.0.0
"""

__version__ = "2.0.0"
__author__ = "PhishGuard Team"

try:
    from .features.url_features_v2 import URLFeatureExtractorV2, FEATURE_NAMES
    from .features.advanced_features import AdvancedFeatureExtractor
    from .features.explainable_ai import ExplainableAIEngine, FeatureImportanceProvider
except ImportError:  # pragma: no cover - fallback for direct local execution
    from features.url_features_v2 import URLFeatureExtractorV2, FEATURE_NAMES
    from features.advanced_features import AdvancedFeatureExtractor
    from features.explainable_ai import ExplainableAIEngine, FeatureImportanceProvider

__all__ = [
    "URLFeatureExtractorV2",
    "AdvancedFeatureExtractor",
    "ExplainableAIEngine",
    "FeatureImportanceProvider",
    "FEATURE_NAMES",
]
