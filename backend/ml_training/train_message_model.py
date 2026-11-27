"""Train, compare, evaluate, and serialize the 4-class Message Classification ML pipeline (v2.0.0)."""

from __future__ import annotations

import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.ml.features import preprocess_message_text  # noqa: E402

DATA_DIR = BACKEND_DIR / "data" / "processed" / "messages"
ARTIFACTS_DIR = BACKEND_DIR / "app" / "ml" / "artifacts"
RANDOM_SEED = 42
MODEL_VERSION = "message-ml-v2.0.0"


def _load_split(split: str) -> tuple[list[str], list[str]]:
    with (DATA_DIR / f"{split}.csv").open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = [(r["text"], r["label"]) for r in reader]
    return [r[0] for r in rows], [r[1] for r in rows]


def train_and_evaluate() -> dict:
    """Compare Logistic Regression and Random Forest on val, evaluate best on test."""
    X_train, y_train = _load_split("train")
    X_val, y_val = _load_split("val")
    X_test, y_test = _load_split("test")

    candidates = {
        "logistic_regression": Pipeline(
            steps=[
                (
                    "tfidf",
                    TfidfVectorizer(
                        preprocessor=preprocess_message_text,
                        ngram_range=(1, 2),
                        max_features=8000,
                        sublinear_tf=True,
                    ),
                ),
                (
                    "clf",
                    CalibratedClassifierCV(
                        LogisticRegression(
                            max_iter=1000,
                            class_weight="balanced",
                            random_state=RANDOM_SEED,
                        ),
                        cv=3,
                        method="sigmoid",
                    ),
                ),
            ]
        ),
        "random_forest": Pipeline(
            steps=[
                (
                    "tfidf",
                    TfidfVectorizer(
                        preprocessor=preprocess_message_text,
                        ngram_range=(1, 2),
                        max_features=6000,
                        sublinear_tf=True,
                    ),
                ),
                (
                    "clf",
                    CalibratedClassifierCV(
                        RandomForestClassifier(
                            n_estimators=150,
                            class_weight="balanced",
                            random_state=RANDOM_SEED,
                            n_jobs=-1,
                        ),
                        cv=3,
                        method="sigmoid",
                    ),
                ),
            ]
        ),
    }

    val_results: dict[str, dict] = {}
    best_name = ""
    best_f1 = -1.0
    best_model = None

    for name, pipe in candidates.items():
        pipe.fit(X_train, y_train)
        preds = pipe.predict(X_val)
        macro_prec = precision_score(y_val, preds, average="macro", zero_division=0)
        macro_f1 = f1_score(y_val, preds, average="macro", zero_division=0)
        macro_recall = recall_score(y_val, preds, average="macro", zero_division=0)
        val_results[name] = {
            "macro_precision": round(float(macro_prec), 4),
            "macro_f1": round(float(macro_f1), 4),
            "macro_recall": round(float(macro_recall), 4),
        }
        if macro_f1 > best_f1:
            best_f1 = macro_f1
            best_name = name
            best_model = pipe

    assert best_model is not None
    test_preds = best_model.predict(X_test)
    test_probs = best_model.predict_proba(X_test)
    classes = list(best_model.classes_)
    cm = confusion_matrix(y_test, test_preds, labels=classes)

    try:
        roc_ovr = round(
            float(roc_auc_score(y_test, test_probs, multi_class="ovr", average="weighted")),
            4,
        )
    except ValueError:
        roc_ovr = None

    baseline_meta_path = ARTIFACTS_DIR / "backup_v1_0_0" / "message_model_meta.json"
    baseline_comparison = None
    if baseline_meta_path.exists():
        base_meta = json.loads(baseline_meta_path.read_text(encoding="utf-8"))
        baseline_comparison = {
            "baseline_version": base_meta.get("model_version"),
            "baseline_dataset": base_meta.get("dataset"),
            "baseline_test_metrics": base_meta.get("test_metrics"),
        }

    metrics = {
        "model_version": MODEL_VERSION,
        "selected_model": best_name,
        "dataset": "uci_sms_spam_collection_plus_synthetic_phishing_scam_v2",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": RANDOM_SEED,
        "calibrated_probabilities": True,
        "classes": classes,
        "splits": {"train": len(X_train), "val": len(X_val), "test": len(X_test)},
        "validation_comparison": val_results,
        "test_metrics": {
            "accuracy": round(float(accuracy_score(y_test, test_preds)), 4),
            "macro_precision": round(float(precision_score(y_test, test_preds, average="macro", zero_division=0)), 4),
            "macro_recall": round(float(recall_score(y_test, test_preds, average="macro", zero_division=0)), 4),
            "macro_f1": round(float(f1_score(y_test, test_preds, average="macro", zero_division=0)), 4),
            "weighted_f1": round(float(f1_score(y_test, test_preds, average="weighted", zero_division=0)), 4),
            "log_loss": round(float(log_loss(y_test, test_probs, labels=classes)), 4),
            "roc_auc_ovr_weighted": roc_ovr,
            "confusion_matrix": {"labels": classes, "matrix": cm.tolist()},
        },
        "classification_report": classification_report(y_test, test_preds, output_dict=True, zero_division=0),
        "baseline_comparison": baseline_comparison,
    }

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_model, ARTIFACTS_DIR / "message_model_v2.joblib")
    joblib.dump(best_model, ARTIFACTS_DIR / "message_model.joblib")
    (ARTIFACTS_DIR / "message_model_meta.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    print(json.dumps({k: v for k, v in metrics.items() if k != "classification_report"}, indent=2))
    return metrics


if __name__ == "__main__":
    train_and_evaluate()
