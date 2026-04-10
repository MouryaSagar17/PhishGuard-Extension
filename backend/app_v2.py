"""
PhishGuard V2 - Advanced FastAPI Backend

Features:
  - Risk levels (safe/suspicious/phishing) instead of binary
  - URL caching for repeated scans
  - SHAP/feature importance explanations
  - HTML content analysis for multi-modal detection
  - Comprehensive API responses

Endpoints:
  POST /v2/predict     — Predict with explanation
  POST /v2/batch       — Batch prediction
  GET  /v2/model/info  — Model information
  POST /model/reload   — Reload model (admin)
  GET  /health         — Health check
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import pickle
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Optional

import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse, Response

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Repository root
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from features.url_features_v2 import URLFeatureExtractorV2, FEATURE_NAMES
from features.explainable_ai import ExplainableAIEngine

# Configuration
MODEL_VERSION = os.environ.get("PHISHING_MODEL_VERSION", "2.0.0")
DEFAULT_MODEL_PATH = ROOT / "models" / "phishing_model_v2.pkl"


def _resolve_model_path(raw_path: str) -> Path:
    path = Path(raw_path)
    if not path.is_absolute():
        path = ROOT / path
    return path


MODEL_PATH = _resolve_model_path(os.environ.get("PHISHING_MODEL_PATH", str(DEFAULT_MODEL_PATH)))

# Risk thresholds (can be tuned)
RISK_THRESHOLDS = {
    "safe": 0.4,          # 0.0 - 0.4: Safe
    "suspicious": 0.7,    # 0.4 - 0.7: Suspicious
    "phishing": 1.0,      # 0.7 - 1.0: Phishing
}

# Caching
CACHE_ENABLED = os.environ.get("CACHE_ENABLED", "true").lower() == "true"
CACHE_TTL_HOURS = int(os.environ.get("CACHE_TTL_HOURS", "24"))

# Whitelist (from V1)
TRUSTED_DOMAINS = frozenset({
    "google.com", "www.google.com", "gmail.com", "youtube.com",
    "facebook.com", "www.facebook.com", "instagram.com", "twitter.com", "x.com",
    "github.com", "www.github.com", "linkedin.com", "reddit.com",
    "amazon.com", "www.amazon.com", "ebay.com",
    "microsoft.com", "www.microsoft.com", "office.com", "outlook.com",
    "apple.com", "www.apple.com", "icloud.com",
    "wikipedia.org", "www.wikipedia.org",
    "stackoverflow.com", "www.stackoverflow.com",
})

# Manual reputation override for domains that should always be treated as unsafe.
# This is intentionally small and brand-pattern based so it only catches clearly
# known high-risk piracy/malware-style domains.
HIGH_RISK_DOMAIN_MARKERS = frozenset({
    "movierulz",
    "thepiratebay",
    "1337x",
    "rarbg",
})


class SimpleLRUCache:
    """Simple LRU cache for predictions."""

    def __init__(self, max_size: int = 1000, ttl_hours: int = 24):
        self.cache = {}
        self.max_size = max_size
        self.ttl = timedelta(hours=ttl_hours)

    def get(self, key: str) -> Optional[dict]:
        if key not in self.cache:
            return None
        entry = self.cache[key]
        if datetime.now() > entry["expiry"]:
            del self.cache[key]
            return None
        return entry["value"]

    def set(self, key: str, value: dict) -> None:
        if len(self.cache) >= self.max_size:
            # Remove oldest entry
            oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k]["expiry"])
            del self.cache[oldest_key]
        
        self.cache[key] = {
            "value": value,
            "expiry": datetime.now() + self.ttl,
        }

    def clear(self) -> None:
        self.cache.clear()


app = FastAPI(
    title="PhishGuard V2 API",
    version=MODEL_VERSION,
    description="Advanced phishing detection with explainability"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ALLOW_ORIGINS", "*").split(","),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
_extractor: URLFeatureExtractorV2 | None = None
_artifact: dict[str, Any] | None = None
_explainer: ExplainableAIEngine | None = None
_startup_error: str | None = None
_cache = SimpleLRUCache(max_size=1000, ttl_hours=CACHE_TTL_HOURS) if CACHE_ENABLED else None


def _model_available() -> bool:
    return MODEL_PATH.is_file()


def load_artifact() -> dict[str, Any]:
    global _artifact, _explainer, _extractor, _startup_error
    
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}")
    
    logger.info(f"Loading model from {MODEL_PATH}...")
    with open(MODEL_PATH, "rb") as f:
        try:
            _artifact = pickle.load(f)
        except ModuleNotFoundError as e:
            _startup_error = (
                f"Failed to load model artifact because a dependency is missing: {e}. "
                "Run the API with the same environment that has the training dependencies installed."
            )
            logger.error(_startup_error)
            raise
    
    _extractor = URLFeatureExtractorV2()
    _explainer = ExplainableAIEngine(_artifact, FEATURE_NAMES)
    
    logger.info(f"Model loaded: {_artifact.get('champion_name', 'unknown')}")
    return _artifact


def get_artifact() -> dict[str, Any]:
    if _artifact is None:
        return load_artifact()
    return _artifact


def _predict_vector_sync(x: np.ndarray) -> tuple[int, float]:
    """Get prediction and probability from loaded model."""
    art = get_artifact()
    bundle = art["bundle"]
    kind = bundle["kind"]
    
    if kind == "sklearn_pipeline":
        pipe = bundle["pipeline"]
        proba = pipe.predict_proba(x.reshape(1, -1))[0]
        pred = int(pipe.predict(x.reshape(1, -1))[0])
    elif kind == "sklearn_estimator":
        est = bundle["estimator"]
        proba = est.predict_proba(x.reshape(1, -1))[0]
        pred = int(est.predict(x.reshape(1, -1))[0])
    else:
        raise RuntimeError(f"Unknown bundle kind: {kind}")
    
    phishing_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
    return pred, phishing_prob


def _get_cache_key(url: str) -> str:
    """Generate cache key from URL."""
    return hashlib.sha256(url.encode()).hexdigest()


def _probability_to_risk_level(prob: float) -> dict[str, Any]:
    """Convert probability to risk level."""
    if prob < RISK_THRESHOLDS["safe"]:
        return {"level": "safe", "description": "Safe", "emoji": "🟢"}
    elif prob < RISK_THRESHOLDS["suspicious"]:
        return {"level": "suspicious", "description": "Suspicious", "emoji": "🟡"}
    else:
        return {"level": "phishing", "description": "Phishing", "emoji": "🔴"}


def _is_high_risk_domain(domain: str) -> bool:
    """Return True for domains that match known high-risk brand markers."""
    domain = (domain or "").lower()
    return any(marker in domain for marker in HIGH_RISK_DOMAIN_MARKERS)


def _high_risk_domain_reason(domain: str) -> str:
    return f"Known high-risk domain pattern detected for {domain}"


# ========== Request/Response Models ==========

class PredictRequest(BaseModel):
    url: str = Field(..., min_length=1)
    html_content: Optional[str] = Field(None, description="Optional HTML for multi-modal detection")
    skip_cache: bool = Field(False, description="Force re-prediction even if cached")


class FeatureContribution(BaseModel):
    feature_name: str
    feature_value: float
    contribution_magnitude: float
    contribution_direction: str


class PredictResponse(BaseModel):
    url: str
    risk_level: str
    risk_score: float
    confidence: float
    label: Literal["safe", "phishing"]
    explanation: str
    top_features: list[FeatureContribution]
    model_version: str
    champion_model: str
    timestamp: str
    cached: bool = False


class BatchPredictRequest(BaseModel):
    urls: list[str] = Field(..., min_items=1, max_items=100)


class BatchPredictResponse(BaseModel):
    predictions: list[PredictResponse]
    processed_count: int
    errors: list[dict[str, str]] = []


class ModelInfoResponse(BaseModel):
    version: str
    champion_model: str
    feature_count: int
    risk_thresholds: dict
    training_metrics: dict
    training_date: str


# ========== Endpoints ==========

@app.on_event("startup")
def startup():
    """
    Startup event: Check model availability and provide guidance
    """
    logger.info("=" * 60)
    logger.info("PhishGuard V2 API Startup")
    logger.info("=" * 60)
    
    # Check if model exists
    if not _model_available():
        logger.warning(f"⚠️  MODEL NOT FOUND")
        logger.warning(f"Expected location: {MODEL_PATH}")
        logger.warning(f"")
        logger.warning(f"To train the model, run:")
        logger.warning(f"  python ml/train_v2.py \\")
        logger.warning(f"    --data data/PhiUSIIL_Phishing_URL_Dataset.csv \\")
        logger.warning(f"    --out models/phishing_model_v2.pkl \\")
        logger.warning(f"    --max-rows 10000")
        logger.warning(f"")
        logger.warning(f"API will accept requests but will return 503 Service Unavailable")
        logger.warning(f"until the model is trained.")
        return
    
    # Try to load model
    try:
        load_artifact()
        logger.info(f"✅ Model loaded successfully")
        logger.info(f"   Location: {MODEL_PATH}")
        logger.info(f"   Champion: {_artifact.get('champion_name', 'unknown')}")
        logger.info(f"   Features: {len(FEATURE_NAMES)}")
        logger.info(f"   Cache: {'Enabled' if CACHE_ENABLED else 'Disabled'}")
    except ModuleNotFoundError as e:
        logger.error(f"❌ MODEL LOAD FAILED - Missing dependency: {e}")
        logger.error(f"   Make sure all dependencies are installed:")
        logger.error(f"   pip install -r requirements.txt")
        logger.error(f"   pip install -r ml/requirements.txt")
    except Exception as e:
        logger.error(f"❌ MODEL LOAD FAILED - {type(e).__name__}: {e}")
    
    logger.info("=" * 60)
    logger.info(f"API running at 0.0.0.0 (accessible from extension)")
    logger.info(f"Health: http://127.0.0.1:8765/health")
    logger.info(f"Docs:   http://127.0.0.1:8765/docs")
    logger.info("=" * 60)


@app.get("/")
def root() -> dict[str, Any]:
    return {
        "service": "PhishGuard V2 API",
        "docs": "/docs",
        "health": "/health",
        "predict": "/v2/predict",
        "model_info": "/v2/model/info",
    }


@app.get("/v2/predict")
def predict_help() -> dict[str, Any]:
    """
    Friendly response for browser visits or accidental GET requests.

    The actual prediction endpoint is POST /v2/predict with a JSON body.
    """
    return {
        "message": "Use POST /v2/predict with JSON body {\"url\": \"https://example.com\"}.",
        "example": {
            "method": "POST",
            "url": "/v2/predict",
            "body": {
                "url": "https://example.com",
                "html_content": "<html>...</html>",
                "skip_cache": False,
            },
        },
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)


@app.get("/health")
def health() -> dict[str, Any]:
    """
    Health check endpoint with detailed model status.
    
    Responses:
    - status: "ok" (model ready), "degraded" (no model/error), "error" (exception)
    - model_available: bool
    - startup_error: error message if any
    - cache_enabled: bool
    - suggestions: helpful message if model not available
    """
    try:
        # Attempt lazy load if not already loaded
        if _artifact is None and _model_available() and _startup_error is None:
            try:
                get_artifact()
            except Exception:
                pass
        
        model_ready = _model_available() and _startup_error is None and _artifact is not None
        
        response = {
            "status": "ok" if model_ready else "degraded",
            "version": MODEL_VERSION,
            "model_available": _model_available(),
            "model_loaded": _artifact is not None,
            "cache_enabled": CACHE_ENABLED,
            "cache_ttl_hours": CACHE_TTL_HOURS,
            "startup_error": _startup_error or "",
        }
        
        # Add helpful suggestions if model isn't available
        if not _model_available():
            response["suggestion"] = (
                f"Model not found at {MODEL_PATH}. "
                f"Train it with: python ml/train_v2.py --data data/PhiUSIIL_Phishing_URL_Dataset.csv --out models/phishing_model_v2.pkl"
            )
        
        if model_ready:
            response["model_info"] = {
                "name": _artifact.get("champion_name", "unknown"),
                "features": len(FEATURE_NAMES),
            }
        
        return response
    except Exception as e:
        return {
            "status": "error",
            "reason": str(e),
            "model_available": _model_available(),
            "startup_error": _startup_error or "",
            "suggestion": "Check server logs for error details"
        }


@app.post("/v2/predict")
async def predict(req: PredictRequest) -> PredictResponse:
    """Predict risk level for a URL with explanation."""
    url = req.url.strip()
    
    # Check trusted domains
    from urllib.parse import urlparse
    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = parsed.hostname or ""

    if _is_high_risk_domain(domain):
        return PredictResponse(
            url=url,
            risk_level="phishing",
            risk_score=1.0,
            confidence=1.0,
            label="phishing",
            explanation=_high_risk_domain_reason(domain),
            top_features=[],
            model_version=MODEL_VERSION,
            champion_model=_artifact.get("champion_name", "unknown") if _artifact else "unknown",
            timestamp=datetime.now().isoformat(),
            cached=False,
        )

    if domain in TRUSTED_DOMAINS:
        return PredictResponse(
            url=url,
            risk_level="safe",
            risk_score=0.0,
            confidence=1.0,
            label="safe",
            explanation="Whitelisted domain",
            top_features=[],
            model_version=MODEL_VERSION,
            champion_model=_artifact.get("champion_name", "unknown") if _artifact else "unknown",
            timestamp=datetime.now().isoformat(),
            cached=False,
        )

    if not _model_available():
        raise HTTPException(
            status_code=503,
            detail=f"Model artifact not found at {MODEL_PATH}. Train the model before requesting predictions.",
        )
    if _startup_error:
        raise HTTPException(status_code=503, detail=_startup_error)
    
    # Check cache
    cache_key = _get_cache_key(url)
    if _cache and not req.skip_cache:
        cached_result = _cache.get(cache_key)
        if cached_result:
            cached_result["cached"] = True
            return PredictResponse(**cached_result)
    
    try:
        # Extract features
        if _extractor is None:
            get_artifact()
        
        x = _extractor.transform_one(url, req.html_content or "")
        
        # Predict
        y_pred, y_proba = _predict_vector_sync(x)
        
        # Explain
        if _explainer:
            explanation = _explainer.explain_prediction(x, y_proba, y_pred, url)
            top_features = [
                FeatureContribution(
                    feature_name=f.feature_name,
                    feature_value=f.feature_value,
                    contribution_magnitude=f.contribution_magnitude,
                    contribution_direction=f.contribution_direction,
                )
                for f in explanation.top_contributions
            ]
            explanation_text = explanation.explanation_text
        else:
            top_features = []
            explanation_text = "Safe" if y_pred == 0 else "Phishing detected"
        
        # Risk level
        risk_info = _probability_to_risk_level(y_proba)
        
        # Confidence: higher at extremes (very safe or very phishing), lower in middle (uncertain)
        # At 0.0 or 1.0 (extremes): confidence = min(2.0, max_val) = 1.0
        # At 0.5 (middle): confidence = 0.0, but we set minimum 0.75 to show some confidence always
        confidence = max(abs(y_proba - 0.5) * 2, 0.75)  # Clamp between 0.75 and 1.0
        
        result = {
            "url": url,
            "risk_level": risk_info["level"],
            "risk_score": y_proba,
            "confidence": confidence,
            "label": "phishing" if y_pred == 1 else "safe",
            "explanation": explanation_text,
            "top_features": [f.dict() for f in top_features],
            "model_version": MODEL_VERSION,
            "champion_model": get_artifact().get("champion_name", "unknown"),
            "timestamp": datetime.now().isoformat(),
            "cached": False,
        }
        
        # Cache result
        if _cache:
            _cache.set(cache_key, result)
        
        return PredictResponse(**result)
    
    except Exception as e:
        logger.error(f"Prediction failed for {url}: {e}")
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")


@app.post("/predict")
async def predict_legacy(req: PredictRequest) -> dict:
    """
    Legacy endpoint for backward compatibility with V1 extension.
    Returns V1 response format: {label, phishing_probability, champion_name, model_version}
    """
    logger.debug(f"Legacy /predict endpoint called for: {req.url}")
    
    # Call the V2 predict function to get full prediction
    v2_result = await predict(req)
    
    # Convert V2 response to V1 format for backward compatibility
    return {
        "url": v2_result.url,
        "label": v2_result.label,
        "phishing_probability": v2_result.risk_score,  # V1 field name for risk score
        "model_version": v2_result.model_version,
        "champion_name": v2_result.champion_model,
    }


@app.post("/v2/batch")
async def batch_predict(req: BatchPredictRequest) -> BatchPredictResponse:
    """Batch predict multiple URLs."""
    predictions = []
    errors = []
    
    for url in req.urls:
        try:
            pred = await predict(PredictRequest(url=url))
            predictions.append(pred)
        except Exception as e:
            errors.append({"url": url, "error": str(e)})
    
    return BatchPredictResponse(
        predictions=predictions,
        processed_count=len(predictions),
        errors=errors,
    )


@app.get("/v2/model/info")
def model_info() -> ModelInfoResponse:
    """Get model metadata and training info."""
    with open(ROOT / "evaluation" / "eval_report.json") as f:
        eval_data = json.load(f)
    
    return ModelInfoResponse(
        timestamp=eval_data["timestamp"],
        version=eval_data["version"],
        champion_model=eval_data["champion"],
        feature_count=len(FEATURE_NAMES),
        risk_thresholds=RISK_THRESHOLDS,
        training_metrics=eval_data["results"],
        training_date=eval_data["timestamp"],
    )


@app.post("/v2/cache/clear")
def cache_clear() -> dict[str, str]:
    """Clear prediction cache (admin endpoint)."""
    if _cache:
        _cache.clear()
        return {"status": "ok", "message": "Cache cleared"}
    return {"status": "skip", "message": "Cache not enabled"}


@app.post("/model/reload")
def model_reload() -> dict[str, bool]:
    """Reload model from disk."""
    global _artifact, _explainer, _extractor
    _artifact = None
    _explainer = None
    _extractor = None
    load_artifact()
    return {"ok": True}


if __name__ == "__main__":
    import uvicorn
    
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8765"))
    
    logger.info(f"Starting PhishGuard V2 API on {host}:{port}")
    uvicorn.run(app, host=host, port=port)
