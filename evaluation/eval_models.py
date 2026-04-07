"""
PhishGuard V2 - Model Comparison and Evaluation

Compares:
  - V1 model (original)
  - V2 model (advanced features)
  - Different architectures (RF, SVM, LR, XGBoost)

Generates:
  - Confusion matrices
  - ROC curves
  - Performance comparison plots
  - Detailed evaluation reports
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc, roc_auc_score,
    precision_recall_curve, average_precision_score
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class ModelEvaluator:
    """Comprehensive model evaluation and comparison."""

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("v2/evaluation")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def compare_models(self, 
                       y_true: np.ndarray,
                       predictions: dict[str, dict[str, np.ndarray]]) -> dict[str, Any]:
        """
        Compare multiple models.
        
        Args:
            y_true: Ground truth labels
            predictions: Dict where key=model_name, value={
                'y_pred': predictions,
                'y_proba': probabilities
            }
        """
        logger.info("="*70)
        logger.info("MODEL COMPARISON")
        logger.info("="*70)

        results = {}

        for model_name, pred_dict in predictions.items():
            logger.info(f"\n{model_name}")
            logger.info("-"*70)

            y_pred = pred_dict["y_pred"]
            y_proba = pred_dict["y_proba"]

            # Core metrics
            acc = accuracy_score(y_true, y_pred)
            prec = precision_score(y_true, y_pred, zero_division=0)
            rec = recall_score(y_true, y_pred, zero_division=0)
            f1 = f1_score(y_true, y_pred, zero_division=0)
            
            # ROC and PR metrics
            auc_roc = roc_auc_score(y_true, y_proba)
            ap = average_precision_score(y_true, y_proba)
            
            # Confusion matrix
            tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
            
            # Additional metrics
            specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
            sensitivity = rec  # Same as recall
            fpr, tpr, _ = roc_curve(y_true, y_proba)
            pr_prec, pr_rec, _ = precision_recall_curve(y_true, y_proba)

            results[model_name] = {
                "accuracy": float(acc),
                "precision": float(prec),
                "recall": float(rec),
                "f1_score": float(f1),
                "auc_roc": float(auc_roc),
                "average_precision": float(ap),
                "sensitivity": float(sensitivity),
                "specificity": float(specificity),
                "tp": int(tp),
                "fp": int(fp),
                "tn": int(tn),
                "fn": int(fn),
                "fpr": fpr.tolist(),
                "tpr": tpr.tolist(),
                "pr_precision": pr_prec.tolist(),
                "pr_recall": pr_rec.tolist(),
            }

            # Log metrics
            logger.info(f"Accuracy:              {acc:.4f}")
            logger.info(f"Precision:             {prec:.4f}")
            logger.info(f"Recall:                {rec:.4f}")
            logger.info(f"F1 Score:              {f1:.4f}")
            logger.info(f"AUC-ROC:               {auc_roc:.4f}")
            logger.info(f"Average Precision:     {ap:.4f}")
            logger.info(f"Specificity:           {specificity:.4f}")
            logger.info(f"\nConfusion Matrix:")
            logger.info(f"  True Negatives:      {tn}")
            logger.info(f"  False Positives:     {fp}")
            logger.info(f"  False Negatives:     {fn}")
            logger.info(f"  True Positives:      {tp}")

        return results

    def generate_comparison_table(self, results: dict[str, Any]) -> pd.DataFrame:
        """Generate comparison DataFrame."""
        rows = []
        for model_name, metrics in results.items():
            rows.append({
                "Model": model_name,
                "Accuracy": f"{metrics['accuracy']:.4f}",
                "Precision": f"{metrics['precision']:.4f}",
                "Recall": f"{metrics['recall']:.4f}",
                "F1": f"{metrics['f1_score']:.4f}",
                "AUC-ROC": f"{metrics['auc_roc']:.4f}",
                "Specificity": f"{metrics['specificity']:.4f}",
            })

        df = pd.DataFrame(rows)
        logger.info("\n" + "="*70)
        logger.info("COMPARISON TABLE")
        logger.info("="*70)
        logger.info(df.to_string(index=False))
        return df

    def rank_models(self, results: dict[str, Any]) -> list[tuple[str, float]]:
        """Rank models by F1 score."""
        ranked = sorted(
            results.items(),
            key=lambda x: x[1]["f1_score"],
            reverse=True
        )
        
        logger.info("\n" + "="*70)
        logger.info("MODEL RANKING (by F1 Score)")
        logger.info("="*70)
        for rank, (name, metrics) in enumerate(ranked, 1):
            logger.info(f"{rank}. {name:25} F1={metrics['f1_score']:.4f}")

        return ranked

    def identify_improvements(self, v1_results: dict[str, Any],
                              v2_results: dict[str, Any]) -> dict[str, Any]:
        """Compare V1 vs V2 improvements."""
        logger.info("\n" + "="*70)
        logger.info("V1 vs V2 COMPARISON")
        logger.info("="*70)

        v1_f1 = v1_results.get("f1_score", 0)
        v2_f1 = v2_results.get("f1_score", 0)

        f1_improvement = ((v2_f1 - v1_f1) / max(v1_f1, 0.001)) * 100 if v1_f1 > 0 else 0

        logger.info(f"\nV1 Model:")
        logger.info(f"  F1 Score: {v1_f1:.4f}")
        logger.info(f"  Accuracy: {v1_results.get('accuracy', 0):.4f}")
        logger.info(f"  Recall:   {v1_results.get('recall', 0):.4f}")

        logger.info(f"\nV2 Model:")
        logger.info(f"  F1 Score: {v2_f1:.4f}")
        logger.info(f"  Accuracy: {v2_results.get('accuracy', 0):.4f}")
        logger.info(f"  Recall:   {v2_results.get('recall', 0):.4f}")

        logger.info(f"\nImprovement:")
        logger.info(f"  F1 +{f1_improvement:.2f}%")

        return {
            "v1_f1": v1_f1,
            "v2_f1": v2_f1,
            "f1_improvement_pct": f1_improvement,
            "improvement_absolute": v2_f1 - v1_f1,
        }

    def save_results(self, results: dict[str, Any], filename: str = "evaluation_results.json"):
        """Save evaluation results to JSON."""
        output_path = self.output_dir / filename
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        logger.info(f"\n✓ Results saved to {output_path}")

    def generate_html_report(self, results: dict[str, Any], output_file: str = "report.html"):
        """Generate HTML report with visualizations."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>PhishGuard V2 - Evaluation Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                h1, h2 { color: #333; }
                table { border-collapse: collapse; width: 100%; margin: 20px 0; background: white; }
                th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                th { background: #4CAF50; color: white; }
                .metric { display: inline-block; margin: 10px 20px; padding: 15px; background: white; border-radius: 5px; }
                .metric-value { font-size: 24px; font-weight: bold; color: #4CAF50; }
                .metric-label { color: #666; }
                .section { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }
            </style>
        </head>
        <body>
            <h1>PhishGuard V2 - Model Evaluation Report</h1>
            
            <div class="section">
                <h2>Model Comparison Summary</h2>
                <table>
                    <tr>
                        <th>Model</th>
                        <th>Accuracy</th>
                        <th>Precision</th>
                        <th>Recall</th>
                        <th>F1 Score</th>
                        <th>AUC-ROC</th>
                    </tr>
        """
        
        for model_name, metrics in results.items():
            html += f"""
                    <tr>
                        <td>{model_name}</td>
                        <td>{metrics['accuracy']:.4f}</td>
                        <td>{metrics['precision']:.4f}</td>
                        <td>{metrics['recall']:.4f}</td>
                        <td>{metrics['f1_score']:.4f}</td>
                        <td>{metrics['auc_roc']:.4f}</td>
                    </tr>
            """
        
        html += """
                </table>
            </div>
            
            <div class="section">
                <h2>Key Metrics</h2>
        """
        
        # Add metrics for best model
        best_model = max(results.items(), key=lambda x: x[1]["f1_score"])
        html += f"""
                <div class="metric">
                    <div class="metric-label">Best Model</div>
                    <div class="metric-value">{best_model[0]}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Best F1 Score</div>
                    <div class="metric-value">{best_model[1]['f1_score']:.4f}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Best Accuracy</div>
                    <div class="metric-value">{best_model[1]['accuracy']:.4f}</div>
                </div>
        """
        
        html += """
            </div>
            
            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                    <li>Deploy the model with best F1 score for production</li>
                    <li>Monitor false positive rate to minimize user disruption</li>
                    <li>Regularly update dataset with new phishing samples</li>
                    <li>Track model performance metrics in production</li>
                </ul>
            </div>
        </body>
        </html>
        """
        
        output_path = self.output_dir / output_file
        with open(output_path, "w") as f:
            f.write(html)
        logger.info(f"✓ HTML report saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(description="PhishGuard V2 - Model Evaluation")
    parser.add_argument("--output-dir", type=Path, default=Path("v2/evaluation"),
                        help="Output directory for reports")
    
    args = parser.parse_args()
    
    evaluator = ModelEvaluator(args.output_dir)
    logger.info("Evaluation framework ready")
    logger.info(f"Output directory: {args.output_dir}")


if __name__ == "__main__":
    main()
