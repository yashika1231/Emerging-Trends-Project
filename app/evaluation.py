"""
Evaluation matrix module for phishing detection system.
Tracks predictions against ground-truth labels and computes
classification metrics: accuracy, precision, recall, F1, confusion matrix.
"""
from typing import Dict, List, Optional
import os


class EvaluationTracker:
    """
    Tracks classification predictions against ground-truth labels
    and computes standard evaluation metrics.
    """

    def __init__(self):
        self._predictions: List[Dict] = []

    def record_prediction(
        self,
        email_text: str,
        predicted_label: str,
        actual_label: str,
        confidence: float = 0.0,
        risk_score: float = 0.0,
    ):
        """Record a single prediction for later evaluation."""
        self._predictions.append({
            "email_snippet": email_text[:100] + "..." if len(email_text) > 100 else email_text,
            "predicted": predicted_label.lower(),
            "actual": actual_label.lower(),
            "confidence": round(confidence, 4),
            "risk_score": round(risk_score, 4),
            "correct": predicted_label.lower() == actual_label.lower(),
        })

    def get_metrics(self) -> Dict:
        """
        Compute evaluation metrics from recorded predictions.

        Returns:
            dict with accuracy, precision, recall, f1_score, confusion_matrix,
            total_predictions, and per-prediction details.
        """
        if not self._predictions:
            return {
                "total_predictions": 0,
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "confusion_matrix": {
                    "true_positive": 0,
                    "true_negative": 0,
                    "false_positive": 0,
                    "false_negative": 0,
                },
                "predictions": [],
                "message": "No predictions recorded yet. Run /evaluate to generate metrics.",
            }

        # Confusion matrix counts
        # Positive = phishing, Negative = legitimate
        tp = 0  # Predicted phishing, actually phishing
        tn = 0  # Predicted legitimate, actually legitimate
        fp = 0  # Predicted phishing, actually legitimate
        fn = 0  # Predicted legitimate, actually phishing

        for pred in self._predictions:
            predicted = pred["predicted"]
            actual = pred["actual"]

            if actual == "phishing" and predicted == "phishing":
                tp += 1
            elif actual == "legitimate" and predicted == "legitimate":
                tn += 1
            elif actual == "legitimate" and predicted == "phishing":
                fp += 1
            elif actual == "phishing" and predicted == "legitimate":
                fn += 1

        total = len(self._predictions)
        correct = tp + tn

        # Metrics
        accuracy = correct / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * (precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return {
            "total_predictions": total,
            "correct_predictions": correct,
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": {
                "true_positive": tp,
                "true_negative": tn,
                "false_positive": fp,
                "false_negative": fn,
            },
            "predictions": self._predictions,
        }

    def reset(self):
        """Clear all recorded predictions."""
        self._predictions.clear()

    @property
    def count(self) -> int:
        return len(self._predictions)


def load_labeled_emails(data_dir: str = "data") -> List[Dict[str, str]]:
    """
    Load labeled email samples from the data directory for evaluation.
    Uses the existing phishing_samples.txt and legitimate_samples.txt files.

    Returns:
        List of dicts with 'text' and 'label' keys
    """
    labeled_emails = []

    phishing_path = os.path.join(data_dir, "phishing_samples.txt")
    legitimate_path = os.path.join(data_dir, "legitimate_samples.txt")

    if os.path.exists(phishing_path):
        emails = _parse_email_file(phishing_path)
        for email in emails:
            labeled_emails.append({"text": email, "label": "phishing"})

    if os.path.exists(legitimate_path):
        emails = _parse_email_file(legitimate_path)
        for email in emails:
            labeled_emails.append({"text": email, "label": "legitimate"})

    return labeled_emails


def _parse_email_file(filepath: str) -> List[str]:
    """Parse email text file separated by ---EMAIL--- markers."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    emails = []
    raw_emails = content.split("---EMAIL---")
    for email in raw_emails:
        email = email.strip()
        if email:
            emails.append(email)

    return emails


# Global singleton
evaluation_tracker = EvaluationTracker()
