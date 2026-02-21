#  🛡️ MalUrl-InOrder — Distributed Malicious URL Detection System

> **Course:** *Cyber Attack Detection Methods*   
> **Project Type:** End-to-end **distributed** system in **Docker** (Frontend + Backend + Queue + Workers)

---

#  📌 Quick Start (Run Guide)

This repository includes a dedicated run guide:  
🟨 **RUN_INSTRUCTIONS.md** 🟨

> Open it first for copy-paste commands and troubleshooting.

---

## 📦 Dataset (for Training)

The full training dataset is **not included** in this repository.

Download `malicious_phish.csv` from Kaggle:
- https://www.kaggle.com/code/thaibaoui/project-ia-4/input

Place the file here:
- `backend/models/data/malicious_phish.csv`

Then follow: **RUN_INSTRUCTIONS.md → Train Model**

---

---

# 📦 Model Handling (Training inside Docker)

⚠️ **The trained model file is NOT included in this repository** (≈ **2GB**).  
This project is **code-first**: you generate the model locally **inside Docker**.

✅ Training produces:
- `backend/models/ml_model.pkl`

➡️ For the full training commands (including the FULL recommended run with LM + trigrams + calibration), see:  
🟨 **RUN_INSTRUCTIONS.md → Section 4 (Train Model)** 🟨

After training, restart backend + worker:
```bash
docker compose restart backend worker
```
---

#  🎯 Project Goal

The goal of this project is to build a **scalable, queue-based cyber-attack detection system** that can:
- Accept URL inputs via a **Web UI** and **FastAPI endpoints**
- Push requests to a **Redis queue**
- Process them asynchronously using **Celery workers**
- Return predictions back to the user
- Train a model inside Docker (code-only submission) and keep the system reproducible

---

#  🧠 What the System Detects

The system classifies URLs into **4 classes**:
- **benign**
- **defacement**
- **malware**
- **phishing**

This is a **multiclass** malicious URL classification task.

---

#  🏗️ Architecture Overview

**Services (Docker Compose):**
- **frontend**: Nginx static UI (http://localhost:8080)
- **backend**: FastAPI service (http://localhost:8000) + OpenAPI docs (http://localhost:8000/docs)
- **redis**: message broker / queue
- **worker**: Celery worker(s) processing jobs from the queue

**Flow:**
1. User submits a URL in the UI (or via API).
2. Backend enqueues a task in Redis.
3. Worker consumes the task, extracts features, runs the ML model.
4. Prediction is returned and displayed in the UI / returned from API.

---

---

## 📸 Figures / Assets

![Comparison & Our Advantage](docs/assets/Comparison%20%26%20Our%20Advantage.png)

![Baseline Comparison](docs/assets/Graph-comparison.png)

[📄 Project Presentation (PDF)](docs/assets/Url%20classification%20presentation.pdf)

---


#  ✅ Proof the System is Running 

Example output (your environment may differ):
- `malurl-inorder-backend-1` (FastAPI)
- `malurl-inorder-worker-1` (Celery)
- `malurl-inorder-redis-1` (Queue)
- `malurl-inorder-frontend-1` (UI)

---

#  🧪 Machine Learning Approach

The ML pipeline is designed to maximize accuracy while remaining lightweight and reproducible in Docker.

**Key elements:**
- **URL normalization**
- **Lexical / structural features**
- **Hashed trigram features** (character 3-grams, bucketed)
- **Benign language-model (LM) hashing features** (host/path/query)
- **Random Forest classifier**
- **Probability calibration (sigmoid)** + validation-based confidence threshold

The model bundle is saved as:
- `backend/models/ml_model.pkl`

Reports are saved under:
- `backend/models/reports/`  
- (and archived per-run under `backend/models/reports/runs/<timestamp>/`)

---

#  📊 Latest Training Results 

These are example metrics produced by a successful full training run:
- **Accuracy:** ~0.955
- **Macro F1:** ~0.943
- **Phishing Recall:** ~0.824  
- **Best confidence threshold (VAL):** 0.3  
- Confusion matrices exported to CSV for direct inclusion in the report

**Runtime Breakdown :**
- Featurize train: ~46 min
- Random Forest training: ~32 min
- Total: ~1h 45m

---

#  📁 Repository Structure 

Typical structure:
- `docker-compose.yaml`
- `backend/` (FastAPI + training + model artifacts)
- `worker/` (Celery consumer / inference runner)
- `frontend/` (static UI via Nginx)
- `RUN_INSTRUCTIONS.md` (step-by-step run & troubleshooting)

---

#  📝 Deliverables & Reporting (What to Include)

For the course report, this project provides:
- **Experimental results** (classification report, macro-f1, accuracy, recall)
- **Confusion matrices** (CSV)
- **Run configuration** (env vars saved inside report JSON)
- **Direct comparison against related work** (two selected papers)
- **System architecture proof** (Docker Compose running services, queue-based design)



---

#  🔐 Code-Only Submission Policy

This repository is intended to be **code-only**:
- ✅ The model is trained locally (inside Docker).
- ✅ The `.pkl` model artifact is generated during training.

---

#  🧩 Troubleshooting 

If UI works but predictions fail:
- Make sure the model exists (`ml_model.pkl` was generated).
- Restart services:
  - `docker compose restart backend worker`

If ports conflict:
- Change `8080` / `8000` in `docker-compose.yaml` or stop the conflicting process.

For full troubleshooting instructions go to this file in root:
🟨 **RUN_INSTRUCTIONS.md** 🟨

---

#  📜 License / Notes

This project was built as part of the academic course:
**Cyber Attack Detection Methods**.  
It demonstrates both **ML performance** and a **distributed, queue-based architecture** under Docker.


