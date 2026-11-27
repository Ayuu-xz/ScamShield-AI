"""Train, compare, and independently evaluate the real-world Message Classification ML pipeline (v3.0.0)."""

from __future__ import annotations

import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import psutil
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
from sklearn.pipeline import FeatureUnion, Pipeline

BACKEND_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from app.ml.features import preprocess_message_text  # noqa: E402

DATA_DIR = BACKEND_DIR / "data" / "processed" / "messages"
ARTIFACTS_DIR = BACKEND_DIR / "app" / "ml" / "artifacts"
RANDOM_SEED = 42
MODEL_VERSION = "message-ml-v3.0.0"


def _load_split(filename: str) -> tuple[list[str], list[str], list[str]]:
    with (DATA_DIR / filename).open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = [(r["text"], r["label"], r.get("source", "unknown")) for r in reader]
    return [r[0] for r in rows], [r[1] for r in rows], [r[2] for r in rows]


def _build_text_features() -> FeatureUnion:
    return FeatureUnion(
        transformer_list=[
            (
                "word_tfidf",
                TfidfVectorizer(
                    preprocessor=preprocess_message_text,
                    ngram_range=(1, 2),
                    max_features=12000,
                    sublinear_tf=True,
                ),
            ),
            (
                "char_tfidf",
                TfidfVectorizer(
                    preprocessor=preprocess_message_text,
                    analyzer="char_wb",
                    ngram_range=(3, 5),
                    max_features=10000,
                    sublinear_tf=True,
                ),
            ),
        ]
    )


def _evaluate_multiclass(model: Pipeline, X: list[str], y: list[str], labels_order: list[str]) -> dict:
    t0 = time.perf_counter()
    preds = model.predict(X)
    probs = model.predict_proba(X)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    cm = confusion_matrix(y, preds, labels=labels_order)
    try:
        roc_ovr = round(float(roc_auc_score(y, probs, multi_class="ovr", average="weighted")), 4)
    except ValueError:
        roc_ovr = None

    return {
        "support": len(y),
        "accuracy": round(float(accuracy_score(y, preds)), 4),
        "macro_precision": round(float(precision_score(y, preds, average="macro", zero_division=0)), 4),
        "macro_recall": round(float(recall_score(y, preds, average="macro", zero_division=0)), 4),
        "macro_f1": round(float(f1_score(y, preds, average="macro", zero_division=0)), 4),
        "weighted_f1": round(float(f1_score(y, preds, average="weighted", zero_division=0)), 4),
        "log_loss": round(float(log_loss(y, probs, labels=labels_order)), 4),
        "roc_auc_ovr_weighted": roc_ovr,
        "inference_latency_ms_per_sample": round(elapsed_ms / max(1, len(X)), 4),
        "confusion_matrix": {"labels": labels_order, "matrix": cm.tolist()},
        "classification_report": classification_report(y, preds, output_dict=True, zero_division=0),
    }


def train_and_evaluate() -> dict:
    """Compare candidates on val, evaluate on real-world test and per-source slices."""
    proc = psutil.Process()
    proc.cpu_percent(interval=None)
    run_start = datetime.now(timezone.utc).isoformat()

    X_train, y_train, _ = _load_split("train.csv")
    X_val, y_val, _ = _load_split("val.csv")
    X_test, y_test, s_test = _load_split("test.csv")

    candidates = {
        "logistic_regression": Pipeline(
            steps=[
                ("features", _build_text_features()),
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
                ("features", _build_text_features()),
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
        t0 = time.perf_counter()
        pipe.fit(X_train, y_train)
        fit_seconds = round(time.perf_counter() - t0, 2)

        preds = pipe.predict(X_val)
        macro_prec = precision_score(y_val, preds, average="macro", zero_division=0)
        macro_f1 = f1_score(y_val, preds, average="macro", zero_division=0)
        macro_recall = recall_score(y_val, preds, average="macro", zero_division=0)
        val_results[name] = {
            "training_duration_seconds": fit_seconds,
            "macro_precision": round(float(macro_prec), 4),
            "macro_f1": round(float(macro_f1), 4),
            "macro_recall": round(float(macro_recall), 4),
        }
        if macro_f1 > best_f1:
            best_f1 = macro_f1
            best_name = name
            best_model = pipe

    assert best_model is not None
    classes = list(best_model.classes_)
    test_eval = _evaluate_multiclass(best_model, X_test, y_test, classes)

    # Source-level accuracy/F1 breakdown on real-world test.csv
    source_eval = {}
    for src in sorted(set(s_test)):
        idxs = [i for i, s in enumerate(s_test) if s == src]
        sx, sy = [X_test[i] for i in idxs], [y_test[i] for i in idxs]
        sp = best_model.predict(sx)
        source_eval[src] = {
            "support": len(sx),
            "accuracy": round(float(accuracy_score(sy, sp)), 4),
            "macro_f1": round(float(f1_score(sy, sp, average="macro", zero_division=0)), 4),
        }

    # Compare against v2.0.0 baseline on the new real-world test.csv
    v2_comparison = None
    v2_path = ARTIFACTS_DIR / "backup_v2_0_0" / "message_model.joblib"
    if v2_path.exists():
        v2_model = joblib.load(v2_path)
        v2_preds = v2_model.predict(X_test)
        v2_comparison = {
            "baseline_version": "message-ml-v2.0.0",
            "v2_on_new_real_world_test_accuracy": round(float(accuracy_score(y_test, v2_preds)), 4),
            "v2_on_new_real_world_test_weighted_f1": round(float(f1_score(y_test, v2_preds, average="weighted", zero_division=0)), 4),
            "v3_on_new_real_world_test_accuracy": test_eval["accuracy"],
            "v3_on_new_real_world_test_macro_f1": test_eval["macro_f1"],
            "v3_on_new_real_world_test_weighted_f1": test_eval["weighted_f1"],
        }

    run_end = datetime.now(timezone.utc).isoformat()
    rss_mb = round(proc.memory_info().rss / (1024 * 1024), 1)
    cpu_pct = round(proc.cpu_percent(interval=None), 1)

    metrics = {
        "model_version": MODEL_VERSION,
        "selected_model": best_name,
        "dataset": "uci_sms_plus_mendeley_10191_plus_mishra_soni_5971_v3",
        "training_started_at": run_start,
        "trained_at": run_end,
        "random_seed": RANDOM_SEED,
        "calibrated_probabilities": True,
        "resource_usage": {"peak_or_end_rss_mb": rss_mb, "process_cpu_percent": cpu_pct},
        "classes": classes,
        "splits": {"train": len(X_train), "val": len(X_val), "test": len(X_test)},
        "validation_comparison": val_results,
        "test_metrics": {k: v for k, v in test_eval.items() if k != "classification_report"},
        "classification_report": test_eval["classification_report"],
        "source_level_test_metrics": source_eval,
        "baseline_comparison": v2_comparison,
    }

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_model, ARTIFACTS_DIR / "message_model_v3.joblib", compress=3)
    joblib.dump(best_model, ARTIFACTS_DIR / "message_model.joblib", compress=3)
    (ARTIFACTS_DIR / "message_model_meta.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in metrics.items() if k != "classification_report"}, indent=2))
    return metrics


if __name__ == "__main__":
    train_and_evaluate()
