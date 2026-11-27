"""Train, compare, evaluate, and serialize the URL Phishing ML pipeline."""

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
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.ml.features import extract_url_lexical_matrix  # noqa: E402

DATA_DIR = BACKEND_DIR / "data" / "processed" / "urls"
ARTIFACTS_DIR = BACKEND_DIR / "app" / "ml" / "artifacts"
RANDOM_SEED = 42
MODEL_VERSION = "url-ml-v1.0.0"


def _load_split(split: str) -> tuple[list[str], list[str]]:
    with (DATA_DIR / f"{split}.csv").open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = [(r["url"], r["label"]) for r in reader]
    return [r[0] for r in rows], [r[1] for r in rows]


def _build_feature_union() -> FeatureUnion:
    return FeatureUnion(
        transformer_list=[
            (
                "char_tfidf",
                TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=3000),
            ),
            (
                "lexical",
                Pipeline(
                    steps=[
                        ("extract", FunctionTransformer(extract_url_lexical_matrix, validate=False)),
                        ("scale", StandardScaler()),
                    ]
                ),
            ),
        ]
    )


def train_and_evaluate() -> dict:
    """Compare Logistic Regression and Random Forest on val, evaluate best on test."""
    X_train, y_train = _load_split("train")
    X_val, y_val = _load_split("val")
    X_test, y_test = _load_split("test")

    candidates = {
        "logistic_regression": Pipeline(
            steps=[
                ("features", _build_feature_union()),
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
                ("features", _build_feature_union()),
                (
                    "clf",
                    RandomForestClassifier(
                        n_estimators=150,
                        class_weight="balanced",
                        random_state=RANDOM_SEED,
                        n_jobs=-1,
                    ),
                ),
            ]
        ),
    }

    val_results: dict[str, dict] = {}
    best_name = ""
    best_score = -1.0
    best_model = None

    for name, pipe in candidates.items():
        pipe.fit(X_train, y_train)
        preds = pipe.predict(X_val)
        phish_recall = recall_score(y_val, preds, pos_label="Phishing")
        phish_f1 = f1_score(y_val, preds, pos_label="Phishing")
        val_results[name] = {
            "phishing_recall": round(float(phish_recall), 4),
            "phishing_f1": round(float(phish_f1), 4),
        }
        # Prioritize phishing recall + F1 to minimize false negatives
        composite = 0.6 * phish_recall + 0.4 * phish_f1
        if composite > best_score:
            best_score = composite
            best_name = name
            best_model = pipe

    assert best_model is not None
    test_preds = best_model.predict(X_test)
    classes = list(best_model.classes_)
    phish_idx = classes.index("Phishing")
    test_probs = best_model.predict_proba(X_test)[:, phish_idx]
    y_test_bin = [1 if y == "Phishing" else 0 for y in y_test]

    cm = confusion_matrix(y_test, test_preds, labels=["Legitimate", "Phishing"])
    tn, fp, fn, tp = int(cm[0][0]), int(cm[0][1]), int(cm[1][0]), int(cm[1][1])

    metrics = {
        "model_version": MODEL_VERSION,
        "selected_model": best_name,
        "dataset": "synthetic_defensive_urls_v1",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": RANDOM_SEED,
        "calibrated_probabilities": True,
        "classes": classes,
        "validation_comparison": val_results,
        "test_metrics": {
            "precision_phishing": round(float(precision_score(y_test, test_preds, pos_label="Phishing")), 4),
            "recall_phishing": round(float(recall_score(y_test, test_preds, pos_label="Phishing")), 4),
            "f1_phishing": round(float(f1_score(y_test, test_preds, pos_label="Phishing")), 4),
            "roc_auc": round(float(roc_auc_score(y_test_bin, test_probs)), 4),
            "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        },
        "classification_report": classification_report(y_test, test_preds, output_dict=True),
    }

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_model, ARTIFACTS_DIR / "url_model.joblib")
    (ARTIFACTS_DIR / "url_model_meta.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    print(json.dumps(metrics, indent=2))
    return metrics


if __name__ == "__main__":
    train_and_evaluate()
