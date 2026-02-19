# worker/worker.py

import os
import pickle
import numpy as np
from urllib.parse import urlparse
from celery import Celery

# Import unified extractor (from mounted backend/models)
from models.feature_extractor import extract_feature_vector, normalize_url


celery_app = Celery(
    "worker",
    broker=os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/0")
)

MODEL_PATH = "models/ml_model.pkl"
bundle = None

SAFE_DOMAINS = [
    "google.com", "google.co.il", "bing.com", "yahoo.com", "duckduckgo.com", "wikipedia.org", "cloudflare.com",
    "openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "perplexity.ai", "gemini.google.com", "midjourney.com",
    "linkedin.com", "github.com", "facebook.com", "instagram.com", "twitter.com", "x.com", "reddit.com", "whatsapp.com",
    "youtube.com", "netflix.com","overleaf.com", "disneyplus.com", "spotify.com", "twitch.tv", "primevideo.com", "hulu.com",
    "microsoft.com", "apple.com", "amazon.com", "zoom.us", "slack.com", "discord.com", "canva.com", "dropbox.com",
    "wix.com", "fiverr.com",
    "ariel.ac.il", "ynet.co.il", "mako.co.il", "walla.co.il", "haaretz.co.il", "n12.co.il"
]


def load_bundle():
    global bundle
    if bundle is None:
        with open(MODEL_PATH, "rb") as f:
            bundle = pickle.load(f)
    return bundle


@celery_app.task(name="worker.predict_url")
def predict_url(job_id, url):
    try:
        b = load_bundle()

        # 1) Normalize (same as training)
        url_norm = normalize_url(url)

        # 2) Domain extraction (whitelist)
        parsed_url = urlparse(url_norm)
        domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path.split('/')[0]
        domain = domain.lower().replace("www.", "")

        for safe_d in SAFE_DOMAINS:
            if domain == safe_d or domain.endswith("." + safe_d):
                return {
                    "url": url,
                    "prediction": "Benign",
                    "status": "success",
                    "note": "Validated via Global Whitelist",
                    "confidence": 1.0
                }

        # 3) Feature vector (base + trigrams + LM)
        x = extract_feature_vector(
            url_norm,
            trigram_buckets=int(b["trigram_buckets"]),
            lm_tables=b["lm_tables"],
            lm_meta=b["lm_meta"],
        ).reshape(1, -1)

        # 4) Predict probabilities (calibrated if available)
        if b.get("use_calibrator") and b.get("calibrator") is not None:
            probs = b["calibrator"].predict_proba(x)[0]
        else:
            probs = b["model"].predict_proba(x)[0]

        max_prob = float(np.max(probs))
        pred_idx = int(np.argmax(probs))

        # 5) Threshold (from training scan)
        thr = float(b.get("threshold_best", 0.65))

        if max_prob >= thr:
            final_label = b["idx_to_label"].get(pred_idx, "unknown")
            note = f"Classified with confidence ({max_prob*100:.1f}%), threshold={thr}"
        else:
            final_label = "benign"
            note = f"Low confidence ({max_prob*100:.1f}%) < threshold={thr} => default Benign"

        # Pretty label mapping
        pretty = {
            "benign": "Benign",
            "defacement": "Defacement",
            "malware": "Malware",
            "phishing": "Phishing"
        }
        pred_out = pretty.get(final_label, final_label)

        return {
            "url": url,
            "prediction": pred_out,
            "status": "success",
            "confidence": max_prob,
            "note": note
        }

    except Exception as e:
        return {"error": str(e), "status": "failed"}
