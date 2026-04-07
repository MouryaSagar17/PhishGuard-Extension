"""
PhishGuard V2 - Explainable AI (XAI) Module

Provides:
  - SHAP feature importance explanations
  - Feature importance from model
  - Risk attribution to specific features
  - Explanations for extension UI display
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class FeatureExplanation:
    """Single feature contribution to prediction."""

    feature_name: str
    feature_value: float
    contribution_magnitude: float  # Absolute impact
    contribution_direction: str  # "positive" (phishing) or "negative" (safe)


@dataclass
class PredictionExplanation:
    """Complete explanation for a prediction."""

    url: str
    predicted_label: str
    predicted_probability: float
    base_value: float  # Model's average prediction
    top_contributions: list[FeatureExplanation]  # Top 5-7 contributing features
    risk_level: str  # "safe", "suspicious", "phishing"
    risk_score: float  # 0.0 to 1.0
    explanation_text: str  # Human-readable summary


class ExplainableAIEngine:
    """
    Provides explanations for model predictions.
    Supports both SHAP-based (tree models) and feature importance methods.
    """

    def __init__(self, model_artifact: dict[str, Any], feature_names: list[str]):
        """
        Args:
            model_artifact: Trained model bundle from training pipeline
            feature_names: List of feature names in same order as features
        """
        self.model_artifact = model_artifact
        self.feature_names = feature_names
        self.explainer = None
        self._init_explainer()

    def _init_explainer(self):
        """Initialize SHAP explainer based on model type."""
        try:
            import shap # pyright: ignore[reportMissingImports]
        except ImportError:
            logger.warning("SHAP not available. Using feature importance fallback.")
            return

        bundle = self.model_artifact["bundle"]
        kind = bundle["kind"]

        try:
            if kind == "sklearn_pipeline":
                pipe = bundle["pipeline"]
                model = pipe.named_steps.get("model") or pipe[-1]
            elif kind == "sklearn_estimator":
                model = bundle["estimator"]
            else:
                logger.warning(f"Unsupported model type for SHAP: {kind}")
                return

            # Use TreeExplainer for tree-based models
            if hasattr(model, "feature_importances_"):
                self.explainer = shap.TreeExplainer(model)
                logger.info("SHAP TreeExplainer initialized")
            else:
                logger.warning(f"Model type {type(model)} not directly supported by SHAP")
        except Exception as e:
            logger.warning(f"Failed to initialize SHAP explainer: {e}")

    def explain_prediction(
        self,
        x: np.ndarray,
        y_proba: float,
        y_pred: int,
        url: str,
    ) -> PredictionExplanation:
        """
        Explain model prediction for a single sample.

        Args:
            x: Feature vector
            y_proba: Phishing probability from model
            y_pred: Binary prediction (0=safe, 1=phishing)
            url: Original URL being classified

        Returns:
            PredictionExplanation with top contributing features
        """
        predicted_label = "phishing" if y_pred == 1 else "safe"
        risk_level, risk_score = self._probability_to_risk_level(y_proba)

        # Get top contributing features
        top_features = self._get_top_features(x, y_proba)

        # Generate human-readable explanation
        explanation_text = self._generate_explanation_text(
            url, predicted_label, risk_level, top_features
        )

        return PredictionExplanation(
            url=url,
            predicted_label=predicted_label,
            predicted_probability=float(y_proba),
            base_value=0.5,  # Model average (placeholder)
            top_contributions=top_features,
            risk_level=risk_level,
            risk_score=risk_score,
            explanation_text=explanation_text,
        )

    def _get_top_features(
        self, x: np.ndarray, y_proba: float, top_k: int = 7
    ) -> list[FeatureExplanation]:
        """
        Extract top contributing features.
        Falls back to simple importance if SHAP unavailable.
        """
        explanations = []

        # Try SHAP if available
        if self.explainer is not None:
            try:
                import shap # pyright: ignore[reportMissingImports]

                x_2d = x.reshape(1, -1)
                shap_values = self.explainer.shap_values(x_2d)

                # For binary classification, use phishing class
                if isinstance(shap_values, list):
                    shap_vals = shap_values[1][0]  # Phishing class
                else:
                    shap_vals = shap_values[0]

                # Get top features by absolute SHAP value
                top_idxs = np.argsort(np.abs(shap_vals))[-top_k:][::-1]

                for idx in top_idxs:
                    direction = "positive" if shap_vals[idx] > 0 else "negative"
                    explanations.append(
                        FeatureExplanation(
                            feature_name=self.feature_names[idx],
                            feature_value=float(x[idx]),
                            contribution_magnitude=float(np.abs(shap_vals[idx])),
                            contribution_direction=direction,
                        )
                    )
                return explanations
            except Exception as e:
                logger.debug(f"SHAP explanation failed, fallback to feature importance: {e}")

        # Fallback: use permutation importance heuristics
        return self._get_top_features_fallback(x, y_proba, top_k)

    def _get_top_features_fallback(
        self, x: np.ndarray, y_proba: float, top_k: int = 7
    ) -> list[FeatureExplanation]:
        """
        Fallback feature importance using heuristics:
        - High-risk features if they have suspicious values
        - Standard deviation-based importance
        """
        # Feature importance heuristics (map feature names to risk factors)
        risk_feature_map = {
            "use_ip": (1.0, "very bad"),  # IP-based URL is phishing indicator
            "domain_very_new": (0.8, "bad"),
            "domain_suspicious_age": (0.7, "bad"),
            "scheme_https": (1.0, "very good"),  # HTTPS is good indicator
            "has_valid_ssl": (0.9, "very good"),
            "suspicious_hits": (0.8, "bad"),
            "tld_suspicious": (0.7, "bad"),
            "ssl_cert_expires_soon": (0.6, "bad"),
            "suspicious_dns": (0.7, "bad"),
            "obfuscated_js": (0.8, "bad"),
            "form_action_mismatch": (0.85, "bad"),
            "login_form_count": (0.6, "moderate"),
            "suspicious_iframe_count": (0.7, "bad"),
        }

        explanations = []
        for idx, fname in enumerate(self.feature_names):
            if fname in risk_feature_map:
                importance, _ = risk_feature_map[fname]
                # Active if feature has non-zero value
                if x[idx] > 0:
                    direction = "positive" if importance > 0.5 and x[idx] > 0 else "negative"
                    explanations.append(
                        FeatureExplanation(
                            feature_name=fname,
                            feature_value=float(x[idx]),
                            contribution_magnitude=importance * float(x[idx]),
                            contribution_direction=direction,
                        )
                    )

        # Sort by magnitude and return top K
        explanations.sort(key=lambda e: e.contribution_magnitude, reverse=True)
        return explanations[:top_k]

    def _probability_to_risk_level(self, probability: float) -> tuple[str, float]:
        """
        Convert probability to risk level.

        Returns:
            (risk_level: str, risk_score: float)
            - safe: 0.0-0.4
            - suspicious: 0.4-0.7
            - phishing: 0.7-1.0
        """
        if probability < 0.4:
            return "safe", probability
        elif probability < 0.7:
            return "suspicious", probability
        else:
            return "phishing", probability

    def _generate_explanation_text(
        self,
        url: str,
        label: str,
        risk_level: str,
        top_features: list[FeatureExplanation],
    ) -> str:
        """Generate human-readable explanation."""
        if not top_features:
            base = f"URL classified as {label}."
        else:
            top_feature_names = [f.feature_name for f in top_features[:3]]
            features_str = ", ".join(top_feature_names)
            base = f"URL classified as {label}. Key factors: {features_str}."

        if risk_level == "phishing":
            return (
                f"{base} Multiple phishing indicators detected. "
                f"Consider avoiding this URL."
            )
        elif risk_level == "suspicious":
            return (
                f"{base} Some suspicious characteristics found. "
                f"Exercise caution."
            )
        else:
            return f"{base} Appears safe based on analysis."


class FeatureImportanceProvider:
    """Extract feature importance from trained models."""

    def __init__(self, model_artifact: dict[str, Any], feature_names: list[str]):
        self.model_artifact = model_artifact
        self.feature_names = feature_names

    def get_feature_importance(self) -> dict[str, float]:
        """
        Get feature importances from model.
        Works with sklearn's feature_importances_ attribute.
        """
        bundle = self.model_artifact["bundle"]
        kind = bundle["kind"]

        importances = {}

        try:
            if kind == "sklearn_pipeline":
                pipe = bundle["pipeline"]
                model = pipe.named_steps.get("model") or pipe[-1]
            elif kind == "sklearn_estimator":
                model = bundle["estimator"]
            else:
                return {}

            if hasattr(model, "feature_importances_"):
                fi = model.feature_importances_
                for fname, importance in zip(self.feature_names, fi):
                    importances[fname] = float(importance)
        except Exception as e:
            logger.warning(f"Failed to extract feature importances: {e}")

        return importances

    def get_top_features(self, top_k: int = 10) -> list[tuple[str, float]]:
        """Get top K most important features."""
        importances = self.get_feature_importance()
        sorted_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)
        return sorted_features[:top_k]
