# backend/models/train.py

import os
import json
import pickle
import time
from datetime import datetime
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    recall_score,
    accuracy_score,
)

try:
    from sklearn.calibration import CalibratedClassifierCV
except Exception:
    CalibratedClassifierCV = None

from feature_extractor import (
    normalize_url,
    build_hashed_lm_tables,
    extract_feature_vector,
    get_feature_names,
)

LABEL_MAP = {"benign": 0, "defacement": 1, "malware": 2, "phishing": 3}
IDX_TO_LABEL = {v: k for k, v in LABEL_MAP.items()}


def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _fmt_seconds(sec: float) -> str:
    sec = max(0.0, float(sec))
    h = int(sec // 3600)
    m = int((sec % 3600) // 60)
    s = int(sec % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _thresholded_predict(probs: np.ndarray, threshold: float) -> np.ndarray:
    """
    Matches worker behavior:
    - if max_prob < threshold => predict benign (0)
    - else predict argmax
    """
    max_prob = np.max(probs, axis=1)
    argm = np.argmax(probs, axis=1)
    y_hat = argm.copy()
    y_hat[max_prob < threshold] = 0
    return y_hat


def _scan_thresholds(probs_val: np.ndarray, y_val: np.ndarray):
    """
    Search threshold on VAL optimizing macro-F1 (keep phishing recall visible).
    """
    candidates = [round(x, 2) for x in np.arange(0.30, 0.96, 0.05)]
    rows = []
    best = None

    for t in candidates:
        y_hat = _thresholded_predict(probs_val, t)
        macro_f1 = f1_score(y_val, y_hat, average="macro")
        phish_recall = recall_score(y_val, y_hat, labels=[3], average=None)[0]
        acc = accuracy_score(y_val, y_hat)

        rows.append(
            {
                "threshold": float(t),
                "macro_f1": float(macro_f1),
                "phishing_recall": float(phish_recall),
                "accuracy": float(acc),
            }
        )

        if best is None or macro_f1 > best["macro_f1"]:
            best = rows[-1]

    return best, rows


def train_model():
    run_started = time.perf_counter()
    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    data_path = os.path.join("data", "malicious_phish.csv")
    if not os.path.exists(data_path):
        print(f"Error: Dataset not found at {data_path}")
        return

    # --------------------------
    # Config knobs (env vars)
    # --------------------------
    trigram_buckets = int(os.getenv("TRIGRAM_BUCKETS", "256"))
    lm_table_size = int(os.getenv("LM_TABLE_SIZE", "50000"))
    lm_max_urls = int(os.getenv("LM_MAX_URLS", "120000"))
    sample_size = int(os.getenv("SAMPLE_SIZE", "0"))  # 0 => full dataset

    use_lm = os.getenv("USE_LM", "1") == "1"
    use_trigram = os.getenv("USE_TRIGRAM", "1") == "1"

    # Progress knobs
    progress_every = int(os.getenv("PROGRESS_EVERY", "50000"))

    # RF knobs
    rf_trees = int(os.getenv("RF_TREES", "400"))
    rf_max_depth_env = os.getenv("RF_MAX_DEPTH", "None")
    rf_max_depth = None if rf_max_depth_env == "None" else int(rf_max_depth_env)
    rf_class_weight = os.getenv("RF_CLASS_WEIGHT", "balanced")

    rf_n_jobs_env = os.getenv("RF_N_JOBS", "-1")
    rf_n_jobs = int(rf_n_jobs_env)  # -1 => all cores
    rf_verbose = int(os.getenv("RF_VERBOSE", "0"))

    # LM_PARTS env: "host,path" or "host,path,query"
    lm_parts_env = os.getenv("LM_PARTS", "host,path")
    lm_parts = [p.strip() for p in lm_parts_env.split(",") if p.strip()]
    if not lm_parts:
        lm_parts = ["host", "path"]

    do_calibrate = os.getenv("CALIBRATE", "1") == "1" and CalibratedClassifierCV is not None
    calibrate_method = os.getenv("CALIBRATE_METHOD", "sigmoid")

    # Reports: keep an archive per run
    reports_root = os.path.join("reports")
    runs_dir = os.path.join(reports_root, "runs", run_ts)
    _ensure_dir(runs_dir)
    _ensure_dir(reports_root)

    print(f"=== RUN {run_ts} ===")
    print(f"Reports folder: {runs_dir}")
    print("Config:")
    print(
        f"  sample_size={sample_size} | use_lm={use_lm} | use_trigram={use_trigram} | "
        f"trigram_buckets={trigram_buckets if use_trigram else 0} | "
        f"lm_parts={lm_parts if use_lm else []} | lm_table_size={lm_table_size if use_lm else None} | "
        f"calibrate={do_calibrate}({calibrate_method if do_calibrate else None}) | "
        f"RF(trees={rf_trees}, n_jobs={rf_n_jobs}, verbose={rf_verbose}, class_weight={rf_class_weight}, max_depth={rf_max_depth_env})"
    )

    # --------------------------
    # Load + prepare data
    # --------------------------
    t0 = time.perf_counter()
    print("Loading dataset...")
    df = pd.read_csv(data_path)
    load_time = time.perf_counter() - t0

    if sample_size and sample_size > 0 and sample_size < len(df):
        print(f"Sampling dataset to {sample_size} rows for faster experimentation...")
        df = df.sample(sample_size, random_state=42).reset_index(drop=True)

    if "url" not in df.columns or "type" not in df.columns:
        raise ValueError("Dataset must have columns: url,type")

    t0 = time.perf_counter()
    print("Normalizing URLs...")
    df["url_norm"] = df["url"].astype(str).apply(normalize_url)
    normalize_time = time.perf_counter() - t0

    df["y"] = df["type"].map(LABEL_MAP)
    if df["y"].isna().any():
        bad = df[df["y"].isna()]["type"].value_counts().to_dict()
        raise ValueError(f"Unknown labels found in dataset: {bad}")

    t0 = time.perf_counter()
    print("Splitting dataset into train/val/test...")
    train_df, test_df = train_test_split(df, test_size=0.20, random_state=42, stratify=df["y"])
    train_df, val_df = train_test_split(train_df, test_size=0.20, random_state=42, stratify=train_df["y"])
    split_time = time.perf_counter() - t0

    # --------------------------
    # Build LM (optional)
    # --------------------------
    lm_tables, lm_meta = None, None
    lm_build_time = 0.0
    if use_lm:
        t0 = time.perf_counter()
        print("Building hashed benign language model (LM) tables...")
        benign_urls = train_df.loc[train_df["y"] == 0, "url_norm"].tolist()
        lm_tables, lm_meta = build_hashed_lm_tables(
            benign_urls,
            table_size=lm_table_size,
            max_urls=lm_max_urls,
            lm_parts=lm_parts
        )
        lm_build_time = time.perf_counter() - t0
        print(
            f"LM built from {lm_meta['used_urls']} benign URLs (cap={lm_max_urls}), "
            f"table_size={lm_table_size}, parts={lm_parts}"
        )
    else:
        print("Skipping LM build (USE_LM=0)")

    # Feature names must match vector length
    feat_names = get_feature_names(
        trigram_buckets=(trigram_buckets if use_trigram else 0),
        lm_parts=(lm_parts if use_lm else [])
    )

    def featurize(url_norm_series: pd.Series, split_name: str) -> np.ndarray:
        n = len(url_norm_series)
        X = np.zeros((n, len(feat_names)), dtype=np.float32)

        start = time.perf_counter()
        fail_count = 0

        # progress/ETA
        last_print_i = 0
        for i, u in enumerate(url_norm_series):
            # Print at i=0? no. Print every progress_every
            if i > 0 and (i % progress_every == 0):
                elapsed = time.perf_counter() - start
                rate = i / elapsed if elapsed > 0 else 0.0
                remaining = n - i
                eta = (remaining / rate) if rate > 0 else 0.0
                pct = (i / n) * 100.0
                print(
                    f"  [{split_name}] Featurized {i}/{n} ({pct:.2f}%) | "
                    f"elapsed={_fmt_seconds(elapsed)} | ETA={_fmt_seconds(eta)} | rate={rate:.1f}/s"
                )
                last_print_i = i

            try:
                X[i, :] = extract_feature_vector(
                    u,
                    trigram_buckets=(trigram_buckets if use_trigram else 0),
                    lm_tables=lm_tables if use_lm else None,
                    lm_meta=lm_meta if use_lm else None,
                    lm_parts=lm_parts if use_lm else []
                )
            except Exception as e:
                X[i, :] = 0.0
                fail_count += 1
                if fail_count <= 10:
                    print(f"[WARN] Featurize failed #{fail_count} at row {i}: {u} | {e}")

        elapsed = time.perf_counter() - start
        if last_print_i != n:
            print(f"  [{split_name}] Featurized {n}/{n} (100.00%) | elapsed={_fmt_seconds(elapsed)}")

        if fail_count > 0:
            print(f"[INFO] Total featurize failures in {split_name}: {fail_count}")

        return X, elapsed

    # --------------------------
    # Featurize splits
    # --------------------------
    print("Featurizing TRAIN...")
    X_train, featurize_train_time = featurize(train_df["url_norm"], "TRAIN")
    y_train = train_df["y"].to_numpy(dtype=np.int32)

    print("Featurizing VAL...")
    X_val, featurize_val_time = featurize(val_df["url_norm"], "VAL")
    y_val = val_df["y"].to_numpy(dtype=np.int32)

    print("Featurizing TEST...")
    X_test, featurize_test_time = featurize(test_df["url_norm"], "TEST")
    y_test = test_df["y"].to_numpy(dtype=np.int32)

    # --------------------------
    # Train model
    # --------------------------
    print("Training Random Forest model...")
    clf = RandomForestClassifier(
        n_estimators=rf_trees,
        max_depth=rf_max_depth,
        n_jobs=rf_n_jobs,
        random_state=42,
        class_weight=rf_class_weight,
        verbose=rf_verbose,
    )

    t0 = time.perf_counter()
    clf.fit(X_train, y_train)
    rf_train_time = time.perf_counter() - t0
    print(f"RF training time: {_fmt_seconds(rf_train_time)}")

    # --------------------------
    # Calibration (optional)
    # --------------------------
    model_for_probs = clf
    cal = None
    calibrate_time = 0.0
    if do_calibrate:
        print(f"Calibrating probabilities using {calibrate_method} on VAL...")
        t0 = time.perf_counter()
        cal = CalibratedClassifierCV(clf, method=calibrate_method, cv="prefit")
        cal.fit(X_val, y_val)
        calibrate_time = time.perf_counter() - t0
        print(f"Calibration time: {_fmt_seconds(calibrate_time)}")
        model_for_probs = cal

    # --------------------------
    # Evaluate
    # --------------------------
    probs_test = model_for_probs.predict_proba(X_test)
    y_pred_raw = np.argmax(probs_test, axis=1)

    print("\n=== Evaluation (RAW argmax) ===")
    print(classification_report(y_test, y_pred_raw, digits=4))
    cm_raw = confusion_matrix(y_test, y_pred_raw)
    macro_f1_raw = f1_score(y_test, y_pred_raw, average="macro")
    phish_recall_raw = recall_score(y_test, y_pred_raw, labels=[3], average=None)[0]
    acc_raw = accuracy_score(y_test, y_pred_raw)

    print("\nSearching best CONFIDENCE threshold on VAL...")
    probs_val = model_for_probs.predict_proba(X_val)
    best_thr, thr_rows = _scan_thresholds(probs_val, y_val)
    print(f"Best threshold (by macro_f1 on VAL): {best_thr}")

    thr = float(best_thr["threshold"])
    y_pred_thr = _thresholded_predict(probs_test, thr)

    print("\n=== Evaluation (THRESHOLDED -> low confidence => benign) ===")
    print(f"Using threshold={thr}")
    print(classification_report(y_test, y_pred_thr, digits=4))
    cm_thr = confusion_matrix(y_test, y_pred_thr)
    macro_f1_thr = f1_score(y_test, y_pred_thr, average="macro")
    phish_recall_thr = recall_score(y_test, y_pred_thr, labels=[3], average=None)[0]
    acc_thr = accuracy_score(y_test, y_pred_thr)

    # --------------------------
    # Save reports (per-run + conventional)
    # --------------------------
    report = {
        "run_id": run_ts,
        "timing": {
            "dataset_load": float(load_time),
            "normalize_urls": float(normalize_time),
            "split": float(split_time),
            "lm_build": float(lm_build_time),
            "featurize_train": float(featurize_train_time),
            "featurize_val": float(featurize_val_time),
            "featurize_test": float(featurize_test_time),
            "rf_train": float(rf_train_time),
            "calibration": float(calibrate_time),
            "total": float(time.perf_counter() - run_started),
        },
        "config": {
            "sample_size": sample_size,
            "use_lm": bool(use_lm),
            "use_trigram": bool(use_trigram),
            "trigram_buckets": trigram_buckets if use_trigram else 0,
            "lm_parts": lm_parts if use_lm else [],
            "lm_table_size": lm_table_size if use_lm else None,
            "lm_max_urls": lm_max_urls if use_lm else None,
            "calibrate": bool(do_calibrate),
            "calibrate_method": calibrate_method if do_calibrate else None,
            "progress_every": progress_every,
            "rf": {
                "trees": rf_trees,
                "n_jobs": rf_n_jobs,
                "verbose": rf_verbose,
                "class_weight": rf_class_weight,
                "max_depth": rf_max_depth_env,
            },
        },
        "raw": {
            "accuracy": float(acc_raw),
            "macro_f1": float(macro_f1_raw),
            "phishing_recall": float(phish_recall_raw),
            "confusion_matrix": cm_raw.tolist(),
        },
        "thresholded": {
            "threshold": float(thr),
            "accuracy": float(acc_thr),
            "macro_f1": float(macro_f1_thr),
            "phishing_recall": float(phish_recall_thr),
            "confusion_matrix": cm_thr.tolist(),
        },
        "threshold_scan_val": thr_rows,
        "labels": IDX_TO_LABEL,
    }

    # Write run-specific
    with open(os.path.join(runs_dir, "eval_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    pd.DataFrame(cm_raw).to_csv(os.path.join(runs_dir, "confusion_matrix_raw.csv"), index=False)
    pd.DataFrame(cm_thr).to_csv(os.path.join(runs_dir, "confusion_matrix_thresholded.csv"), index=False)

    # Also write "latest" conventional files (overwrite)
    with open(os.path.join(reports_root, "eval_report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    pd.DataFrame(cm_raw).to_csv(os.path.join(reports_root, "confusion_matrix_raw.csv"), index=False)
    pd.DataFrame(cm_thr).to_csv(os.path.join(reports_root, "confusion_matrix_thresholded.csv"), index=False)

    # Human-friendly summary
    summary = {
        "run_id": run_ts,
        "raw_accuracy": float(acc_raw),
        "raw_macro_f1": float(macro_f1_raw),
        "thr_accuracy": float(acc_thr),
        "thr_macro_f1": float(macro_f1_thr),
        "best_threshold": float(thr),
        "timing_hms": {k: _fmt_seconds(v) for k, v in report["timing"].items()},
        "reports_dir": runs_dir,
    }
    with open(os.path.join(runs_dir, "run_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\nSaved reports to: {runs_dir}/ (archived)")
    print(f"Also updated: {reports_root}/ (latest)")
    print(f"Total run time: {_fmt_seconds(report['timing']['total'])}")

    # --------------------------
    # Save model bundle
    # --------------------------
    bundle = {
        "model": clf,
        "calibrator": cal,
        "use_calibrator": bool(do_calibrate),
        "threshold_best": float(thr),
        "label_map": LABEL_MAP,
        "idx_to_label": IDX_TO_LABEL,
        "use_lm": bool(use_lm),
        "use_trigram": bool(use_trigram),
        "trigram_buckets": trigram_buckets if use_trigram else 0,
        "lm_parts": lm_parts if use_lm else [],
        "lm_tables": lm_tables,
        "lm_meta": lm_meta,
        "feature_names": feat_names,
        "run_id": run_ts,
    }

    output_path = "ml_model.pkl"
    with open(output_path, "wb") as f:
        pickle.dump(bundle, f)

    print(f"\nModel bundle saved successfully to {output_path}")


if __name__ == "__main__":
    train_model()
