"""
PhishGuard V2 - Fixed training script with correct paths and indentation
"""

from __future__ import annotations

import argparse
import json
import logging
import pickle
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from features.url_features_v2 import URLFeatureExtractorV2, FEATURE_NAMES, bundle_meta


def _try_import_xgb():
    try:
        import xgboost as xgb
        return True
    except ImportError:
        return False


HAS_XGB = _try_import_xgb()


class V2ModelTrainer:
    """Train and evaluate V2 phishing detection models."""

    def __init__(self, random_state: int = 42, enable_network_checks: bool = True):
        self.random_state = random_state
        self.enable_network_checks = enable_network_checks
        self.models = {}
        self.results = {}
        self.best_model = None

    def load_dataset(
        self,
        csv_path: Path,
        label_format: str = "auto",
        max_rows: int = None,
    ) -> tuple[np.ndarray, np.ndarray, list[str]]:
        """Load and preprocess dataset."""
        logger.info(f"Loading dataset from {csv_path}...")
        df = pd.read_csv(csv_path, low_memory=False)

        if max_rows and len(df) > max_rows:
            df = df.sample(n=max_rows, random_state=self.random_state).reset_index(drop=True)
            logger.info(f"Sampled {max_rows} rows")

        # Auto-detect label format
        if label_format == "auto":
            label_format = self._detect_label_format(df)
            logger.info(f"Auto-detected label_format: {label_format}")

        # Parse labels
        cols = {c.lower(): c for c in df.columns}
        if "url" not in cols or "label" not in cols:
            raise ValueError("CSV must contain: url, label")

        url_col = cols["url"]
        lab_col = cols["label"]
        urls = df[url_col].astype(str).tolist()
        y = self._parse_labels(df[lab_col], label_format)

        if len(urls) < 10:
            raise ValueError("Not enough labeled rows")

        # Extract features
        logger.info(f"Extracting features for {len(urls):,} URLs...")
        extractor = URLFeatureExtractorV2(enable_network_checks=self.enable_network_checks)
        X = extractor.transform_many(urls)

        logger.info(f"Dataset: {X.shape[0]} samples, {X.shape[1]} features")
        logger.info(f"Class distribution - Safe: {sum(y==0)}, Phishing: {sum(y==1)}")

        return X, y, urls

    def _detect_label_format(self, df: pd.DataFrame) -> str:
        """Auto-detect label format."""
        lab_col = [c for c in df.columns if c.lower() == "label"][0]
        sample_labels = df[lab_col].astype(str).str.lower().unique()[:5]

        if any(l in ["phishing", "safe"] for l in sample_labels):
            return "strings"
        elif any(l in ["0", "1"] for l in sample_labels):
            if "phiusiil" in df.columns[0].lower():
                return "phiusiil"
            return "binary_phish_one"
        return "strings"

    def _parse_labels(self, labels: pd.Series, fmt: str) -> np.ndarray:
        """Parse labels to binary (0=safe, 1=phishing)."""
        if fmt == "phiusiil":
            # PhiUSIIL: 0=phishing, 1=legitimate (inverted)
            y_num = pd.to_numeric(labels, errors="coerce")
            valid = y_num.notna() & y_num.isin([0, 1])
            return (1 - y_num[valid]).astype(np.int64).to_numpy()
        elif fmt == "binary_phish_one":
            # Kaggle-style: 1=phishing, 0=safe
            return pd.to_numeric(labels, errors="coerce").astype(np.int64).to_numpy()
        else:
            # String labels
            label_map = {
                "phishing": 1, "malicious": 1, "bad": 1, "1": 1, "true": 1, "yes": 1,
                "safe": 0, "legitimate": 0, "benign": 0, "good": 0, "0": 0, "false": 0, "no": 0,
            }
            y_list = []
            for l in labels.astype(str).str.lower().str.strip():
                if l in label_map:
                    y_list.append(label_map[l])
            return np.array(y_list, dtype=np.int64)

    def train_models(self, X_train: np.ndarray, y_train: np.ndarray, selected_models: list[str] = None) -> dict[str, Any]:
        """Train multiple model variants."""
        logger.info("Training model suite...")

        models_config = {
            "random_forest": self._create_rf_model,
            "svm": self._create_svm_model,
            "logistic_regression": self._create_lr_model,
        }

        if HAS_XGB:
            models_config["xgboost"] = self._create_xgb_model
            logger.info("XGBoost available - including in comparison")
        else:
            logger.warning("XGBoost not installed - skipping")

        if selected_models:
            selected = {name.strip().lower() for name in selected_models if name.strip()}
            models_config = {name: fn for name, fn in models_config.items() if name in selected}
            logger.info(f"Training selected models: {', '.join(models_config.keys())}")
            if not models_config:
                raise ValueError("No valid models selected. Choose from: random_forest, svm, logistic_regression, xgboost")

        for name, create_fn in models_config.items():
            logger.info(f"\nTraining {name}...")
            try:
                model = create_fn()
                model.fit(X_train, y_train)
                self.models[name] = model
                logger.info(f"✓ {name} trained")
            except Exception as e:
                logger.error(f"✗ {name} failed: {e}")

        return self.models

    def _create_rf_model(self) -> Pipeline:
        rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            random_state=self.random_state,
            n_jobs=-1,
            class_weight="balanced",
        )
        return Pipeline([("scaler", StandardScaler()), ("model", rf)])

    def _create_svm_model(self) -> Pipeline:
        svm = SVC(kernel="rbf", probability=True, random_state=self.random_state, class_weight="balanced")
        return Pipeline([("scaler", StandardScaler()), ("model", svm)])

    def _create_lr_model(self) -> Pipeline:
        lr = LogisticRegression(max_iter=1000, random_state=self.random_state, class_weight="balanced")
        return Pipeline([("scaler", StandardScaler()), ("model", lr)])

    def _create_xgb_model(self):
        import xgboost as xgb
        return xgb.XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.9,
            colsample_bytree=0.9,
            random_state=self.random_state,
            scale_pos_weight=1.0,
            n_jobs=-1,
            tree_method="hist",
            eval_metric="logloss",
            verbosity=1,
        )

    def evaluate_models(self, X_test: np.ndarray, y_test: np.ndarray) -> dict[str, dict[str, float]]:
        logger.info("\n" + "="*60)
        logger.info("MODEL EVALUATION")
        logger.info("="*60)

        for name, model in self.models.items():
            logger.info(f"\n--- {name.upper()} ---")
            y_pred = model.predict(X_test)
            y_proba = model.predict_proba(X_test)[:, 1]

            acc = accuracy_score(y_test, y_pred)
            prec = precision_score(y_test, y_pred, zero_division=0)
            rec = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            auc = roc_auc_score(y_test, y_proba)

            self.results[name] = {"accuracy": acc, "precision": prec, "recall": rec, "f1": f1, "auc": auc}

            logger.info(f"F1: {f1:.4f}, AUC: {auc:.4f}")

        best_name = max(self.results.keys(), key=lambda k: self.results[k]["f1"])
        self.best_model = (best_name, self.models[best_name])
        logger.info(f"\nCHAMPION: {best_name}")

        return self.results

    def save_champion_model(self, output_path: Path) -> None:
        champion_name, champion_model = self.best_model
        artifact = {
            "timestamp": datetime.now().isoformat(),
            "version": "2.0.0",
            "champion_name": champion_name,
            "bundle": {
                "kind": "sklearn_pipeline" if hasattr(champion_model, "named_steps") else "sklearn_estimator",
                "pipeline" if hasattr(champion_model, "named_steps") else "estimator": champion_model,
            },
            "feature_names": FEATURE_NAMES,
            "metadata": bundle_meta,
            "training_metrics": self.results,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "wb") as f:
            pickle.dump(artifact, f)
        logger.info(f"✓ Model saved to {output_path}")

    def save_evaluation_report(self, output_path: Path) -> None:
        report = {
            "timestamp": datetime.now().isoformat(),
            "version": "2.0.0",
            "champion": self.best_model[0] if self.best_model else None,
            "results": self.results,
        }
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)
        logger.info(f"✓ Report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="PhishGuard V2 Training")
    parser.add_argument("--data", type=Path, default="data/PhiUSIIL_Phishing_URL_Dataset.csv", help="Dataset path")
    parser.add_argument("--max-rows", type=int, default=5000)
    parser.add_argument("--out", type=Path, default="models/phishing_model_v2.pkl")
    parser.add_argument("--eval-out", type=Path, default="evaluation/eval_report.json")
    parser.add_argument(
        "--fast-features",
        action="store_true",
        help="Skip DNS/SSL network checks during feature extraction to speed up training",
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=["xgboost"],
        help="Optional list of models to train: random_forest svm logistic_regression xgboost",
    )

    args = parser.parse_args()

    trainer = V2ModelTrainer(enable_network_checks=not args.fast_features)
    X, y, _ = trainer.load_dataset(args.data, max_rows=args.max_rows)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    trainer.train_models(X_train, y_train, selected_models=args.models)
    trainer.evaluate_models(X_test, y_test)

    trainer.save_champion_model(args.out)
    trainer.save_evaluation_report(args.eval_out)

    logger.info("\n✓ Training complete!")


if __name__ == "__main__":
    main()

