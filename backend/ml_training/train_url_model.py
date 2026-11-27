"""Train, compare, and independently evaluate the URL Phishing ML pipeline (v3.0.0)."""

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
MODEL_VERSION = "url-ml-v3.0.0"


def _load_split(filename: str) -> tuple[list[str], list[str], list[str]]:
    with (DATA_DIR / filename).open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = [(r["url"], r["label"], r.get("source", "unknown")) for r in reader]
    return [r[0] for r in rows], [r[1] for r in rows], [r[2] for r in rows]


def _build_feature_union() -> FeatureUnion:
    return FeatureUnion(
        transformer_list=[
            (
                "char_tfidf",
                TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), max_features=8000, sublinear_tf=True),
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
    t0 = time.perf_counter()
    preds = model.predict(X)
    classes = list(model.classes_)
    phish_idx = classes.index("Phishing")
    probs = model.predict_proba(X)[:, phish_idx]
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    y_bin = [1 if lbl == "Phishing" else 0 for lbl in y]
    cm = confusion_matrix(y, preds, labels=["Legitimate", "Phishing"])
    tn, fp, fn, tp = int(cm[0][0]), int(cm[0][1]), int(cm[1][0]), int(cm[1][1])
    fpr = fp / max(1, fp + tn)
    fnr = fn / max(1, fn + tp)

    roc = round(float(roc_auc_score(y_bin, probs)), 4) if len(set(y_bin)) > 1 else None
    pr = round(float(average_precision_score(y_bin, probs)), 4) if len(set(y_bin)) > 1 else None

    return {
        "support": len(y),
        "accuracy": round(float(accuracy_score(y, preds)), 4),
        "macro_f1": round(float(f1_score(y, preds, average="macro", zero_division=0)), 4),
        "weighted_f1": round(float(f1_score(y, preds, average="weighted", zero_division=0)), 4),
        "precision_phishing": round(float(precision_score(y, preds, pos_label="Phishing", zero_division=0)), 4),
        "recall_phishing": round(float(recall_score(y, preds, pos_label="Phishing", zero_division=0)), 4),
        "f1_phishing": round(float(f1_score(y, preds, pos_label="Phishing", zero_division=0)), 4),
        "fpr": round(float(fpr), 4),
        "fnr": round(float(fnr), 4),
        "roc_auc": roc,
        "pr_auc": pr,
        "brier_score": round(float(brier_score_loss(y_bin, probs)), 4),
        "inference_latency_ms_per_sample": round(elapsed_ms / max(1, len(X)), 4),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "classification_report": classification_report(y, preds, output_dict=True, zero_division=0),
    }


def train_and_evaluate() -> dict:
    """Compare candidates on val, evaluate on unseen-domain & time-separated real-world test sets."""
    proc = psutil.Process()
    proc.cpu_percent(interval=None)
    run_start = datetime.now(timezone.utc).isoformat()

    X_train, y_train, _ = _load_split("train.csv")
    X_val, y_val, _ = _load_split("val.csv")
    X_test, y_test, s_test = _load_split("test.csv")

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
                            n_estimators=100,
                            max_depth=28,
                            min_samples_leaf=2,
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
        t0 = time.perf_counter()
        pipe.fit(X_train, y_train)
        fit_seconds = round(time.perf_counter() - t0, 2)

        preds = pipe.predict(X_val)
        macro_f1 = f1_score(y_val, preds, average="macro", zero_division=0)
        phish_prec = precision_score(y_val, preds, pos_label="Phishing", zero_division=0)
        phish_recall = recall_score(y_val, preds, pos_label="Phishing", zero_division=0)
        phish_f1 = f1_score(y_val, preds, pos_label="Phishing", zero_division=0)
        cm_val = confusion_matrix(y_val, preds, labels=["Legitimate", "Phishing"])
        tn_v, fp_v, fn_v, tp_v = int(cm_val[0][0]), int(cm_val[0][1]), int(cm_val[1][0]), int(cm_val[1][1])
        val_results[name] = {
            "training_duration_seconds": fit_seconds,
            "macro_f1": round(float(macro_f1), 4),
            "phishing_precision": round(float(phish_prec), 4),
            "phishing_recall": round(float(phish_recall), 4),
            "phishing_f1": round(float(phish_f1), 4),
            "fpr": round(fp_v / max(1, fp_v + tn_v), 4),
            "fnr": round(fn_v / max(1, fn_v + tp_v), 4),
        }
        composite = 0.5 * macro_f1 + 0.5 * phish_recall
        if composite > best_score:
            best_score = composite
            best_name = name
            best_model = pipe

    assert best_model is not None
    test_eval = _evaluate_binary(best_model, X_test, y_test)

    # Source-level breakdown on unseen-domain test.csv
    source_eval = {}
    for src in sorted(set(s_test)):
        idxs = [i for i, s in enumerate(s_test) if s == src]
        res = _evaluate_binary(best_model, [X_test[i] for i in idxs], [y_test[i] for i in idxs])
        source_eval[src] = {k: v for k, v in res.items() if k != "classification_report"}

    # Time-separated + unseen-domain PhreshPhish test set
    pp_eval = None
    pp_file = DATA_DIR / "test_phreshphish_unseen.csv"
    if pp_file.exists():
        X_pp, y_pp, _ = _load_split("test_phreshphish_unseen.csv")
        pp_eval = _evaluate_binary(best_model, X_pp, y_pp)

    # Strictly separate synthetic benchmark
    syn_eval = None
    syn_file = DATA_DIR / "benchmark_synthetic.csv"
    if syn_file.exists():
        X_syn, y_syn, _ = _load_split("benchmark_synthetic.csv")
        syn_eval = _evaluate_binary(best_model, X_syn, y_syn)

    # Compare against v2.0.0 baseline on the new time-separated unseen-domain PhreshPhish test
    v2_comparison = None
    v2_path = ARTIFACTS_DIR / "backup_v2_0_0" / "url_model.joblib"
    if v2_path.exists() and pp_eval is not None:
        v2_model = joblib.load(v2_path)
        v2_pp = _evaluate_binary(v2_model, X_pp, y_pp)
        v2_comparison = {
            "baseline_version": "url-ml-v2.0.0",
            "phreshphish_time_unseen_v2": {k: v for k, v in v2_pp.items() if k != "classification_report"},
            "phreshphish_time_unseen_v3": {k: v for k, v in pp_eval.items() if k != "classification_report"},
        }

    run_end = datetime.now(timezone.utc).isoformat()
    rss_mb = round(proc.memory_info().rss / (1024 * 1024), 1)
    cpu_pct = round(proc.cpu_percent(interval=None), 1)

    metrics = {
        "model_version": MODEL_VERSION,
        "selected_model": best_name,
        "dataset": "legitphish_plus_phreshphish_plus_phishtank_v3",
        "training_started_at": run_start,
        "trained_at": run_end,
        "random_seed": RANDOM_SEED,
        "calibrated_probabilities": True,
        "resource_usage": {"peak_or_end_rss_mb": rss_mb, "process_cpu_percent": cpu_pct},
        "classes": list(best_model.classes_),
        "splits": {"train": len(X_train), "val": len(X_val), "test_unseen_domains": len(X_test)},
        "validation_comparison": val_results,
        "test_metrics": {k: v for k, v in test_eval.items() if k != "classification_report"},
        "classification_report": test_eval["classification_report"],
        "source_level_test_metrics": source_eval,
        "time_separated_unseen_domains_eval": {
            "dataset": "phreshphish_test_unseen_domains",
            "metrics": {k: v for k, v in (pp_eval or {}).items() if k != "classification_report"},
        },
        "synthetic_supplementary_eval": {
            "dataset": "synthetic_defensive_urls_v1",
            "metrics": {k: v for k, v in (syn_eval or {}).items() if k != "classification_report"},
        },
        "baseline_comparison": v2_comparison,
    }

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(best_model, ARTIFACTS_DIR / "url_model_v3.joblib", compress=3)
    joblib.dump(best_model, ARTIFACTS_DIR / "url_model.joblib", compress=3)
    (ARTIFACTS_DIR / "url_model_meta.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in metrics.items() if k != "classification_report"}, indent=2))
    return metrics


if __name__ == "__main__":
    train_and_evaluate()
