"""Train, compare, evaluate, and serialize the URL Phishing ML pipeline (v2.0.0)."""

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
    average_precision_score,
    brier_score_loss,
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
MODEL_VERSION = "url-ml-v2.0.0"


def _load_split(filename: str) -> tuple[list[str], list[str]]:
    with (DATA_DIR / filename).open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = [(r["url"], r["label"]) for r in reader]
    return [r[0] for r in rows], [r[1] for r in rows]


def _build_feature_union() -> FeatureUnion:
    return FeatureUnion(
        transformer_list=[
            (
                "char_tfidf",
                TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=5000),
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


def _evaluate_binary(model: Pipeline, X: list[str], y: list[str]) -> dict:
    preds = model.predict(X)
    classes = list(model.classes_)
    phish_idx = classes.index("Phishing")
    probs = model.predict_proba(X)[:, phish_idx]
    y_bin = [1 if lbl == "Phishing" else 0 for lbl in y]

    cm = confusion_matrix(y, preds, labels=["Legitimate", "Phishing"])
    tn, fp, fn, tp = int(cm[0][0]), int(cm[0][1]), int(cm[1][0]), int(cm[1][1])

    return {
        "support": len(y),
        "accuracy": round(float(accuracy_score(y, preds)), 4),
        "precision_phishing": round(float(precision_score(y, preds, pos_label="Phishing")), 4),
        "recall_phishing": round(float(recall_score(y, preds, pos_label="Phishing")), 4),
        "f1_phishing": round(float(f1_score(y, preds, pos_label="Phishing")), 4),
        "roc_auc": round(float(roc_auc_score(y_bin, probs)), 4),
        "pr_auc": round(float(average_precision_score(y_bin, probs)), 4),
        "brier_score": round(float(brier_score_loss(y_bin, probs)), 4),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "classification_report": classification_report(y, preds, output_dict=True),
    }


def train_and_evaluate() -> dict:
    """Compare Logistic Regression and Random Forest on val, evaluate best on test + cross-dataset."""
    X_train, y_train = _load_split("train.csv")
    X_val, y_val = _load_split("val.csv")
    X_test, y_test = _load_split("test.csv")

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
                    CalibratedClassifierCV(
                        RandomForestClassifier(
                            n_estimators=150,
                            max_depth=30,
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
    best_score = -1.0
    best_model = None

    for name, pipe in candidates.items():
        pipe.fit(X_train, y_train)
        preds = pipe.predict(X_val)
        phish_prec = precision_score(y_val, preds, pos_label="Phishing")
        phish_recall = recall_score(y_val, preds, pos_label="Phishing")
        phish_f1 = f1_score(y_val, preds, pos_label="Phishing")
        cm_val = confusion_matrix(y_val, preds, labels=["Legitimate", "Phishing"])
        val_results[name] = {
            "phishing_precision": round(float(phish_prec), 4),
            "phishing_recall": round(float(phish_recall), 4),
            "phishing_f1": round(float(phish_f1), 4),
            "false_negatives": int(cm_val[1][0]),
            "false_positives": int(cm_val[0][1]),
        }
        composite = 0.6 * phish_recall + 0.4 * phish_f1
        if composite > best_score:
            best_score = composite
            best_name = name
            best_model = pipe

    assert best_model is not None
    test_eval = _evaluate_binary(best_model, X_test, y_test)
    classes = list(best_model.classes_)

    cross_dataset_eval = None
    lp_test_file = DATA_DIR / "test_legitphish.csv"
    if lp_test_file.exists():
        X_lp, y_lp = _load_split("test_legitphish.csv")
        cross_dataset_eval = _evaluate_binary(best_model, X_lp, y_lp)

    syn_eval = None
    bench_file = DATA_DIR / "benchmark_synthetic.csv"
    if bench_file.exists():
        X_syn, y_syn = _load_split("benchmark_synthetic.csv")
        syn_eval = _evaluate_binary(best_model, X_syn, y_syn)

    baseline_meta_path = ARTIFACTS_DIR / "backup_v1_0_0" / "url_model_meta.json"
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
        "dataset": "legitphish_mendeley_plus_synthetic_defensive_urls_v2",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": RANDOM_SEED,
        "calibrated_probabilities": True,
        "classes": classes,
        "splits": {"train": len(X_train), "val": len(X_val), "test": len(X_test)},
        "validation_comparison": val_results,
        "test_metrics": {k: v for k, v in test_eval.items() if k != "classification_report"},
        "classification_report": test_eval["classification_report"],
        "dataset_specific_evaluation": {
            "legitphish_test": {
                k: v for k, v in (cross_dataset_eval or {}).items() if k != "classification_report"
            },
            "synthetic_benchmark_test": {
                k: v for k, v in (syn_eval or {}).items() if k != "classification_report"
            },
        },
        "baseline_comparison": baseline_comparison,
    }

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_model, ARTIFACTS_DIR / "url_model_v2.joblib")
    joblib.dump(best_model, ARTIFACTS_DIR / "url_model.joblib")
    (ARTIFACTS_DIR / "url_model_meta.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8"
    )
    print(json.dumps({k: v for k, v in metrics.items() if k != "classification_report"}, indent=2))
    return metrics


if __name__ == "__main__":
    train_and_evaluate()
