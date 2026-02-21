 # MalUrl-InOrder — How to Run 

This project runs a distributed malicious URL detection system using:
- Frontend UI (static HTML/JS served by Nginx)
- Backend API (FastAPI + OpenAPI)
- Redis (message broker / queue)
- Celery Worker(s) (background inference)

---

 ## 0) Prerequisites
- Docker Desktop installed and running
- `docker compose` available (Docker Compose v2)

---

 ## 1) Verify You Are in the Correct Folder 
You must run commands from the project root (the folder that contains `docker-compose.yaml`).

 ### Windows (PowerShell)
 ```powershell
dir
 ```

You should see: `docker-compose.yaml`, `backend/`, `worker/`, `frontend/`.

 ### macOS / Linux (Terminal)
 ```bash
ls
 ```

If you do NOT see those files/folders:
- you are in the wrong directory
- run `cd MalUrl-InOrder` and try again

Optional quick check:
 ```bash
docker compose config
 ```
If this prints a composed config (and not an error), you're in the right place.

---

 ## 2) Build & Start Services 
From the project root:

 ```bash
docker compose up -d --build
 ```

Verify containers are running:

 ```bash
docker compose ps
 ```

---

 ## 3) Access Points
- UI: `http://localhost:8080`
- Backend OpenAPI (Swagger): `http://localhost:8000/docs`

---

---

## 3.5) Dataset (Required for Training)

This repository does **not** include the full dataset.

Download the CSV from Kaggle:
- https://www.kaggle.com/code/thaibaoui/project-ia-4/input

You need:
- `malicious_phish.csv`

Place it at:
- `backend/models/data/malicious_phish.csv`

Then continue to Section 4 (Train Model).

---

 ## 4) Train Model 
This repo is code-first: the model is trained locally via Docker and saved under `backend/models/` due to volume mounts.

 ### 4.1 Basic Training (quick)
 ```bash
docker compose run --rm backend sh -lc "cd /app/models && python train.py"
 ```

 ### 4.2 FULL Training (best results)
Use the FULL command below for the best metrics (LM + trigrams + calibration).

 #### Option A — Windows PowerShell (recommended)
 ```powershell
docker compose run --rm `
  -e SAMPLE_SIZE=0 `
  -e USE_LM=1 -e USE_TRIGRAM=1 `
  -e TRIGRAM_BUCKETS=1024 `
  -e LM_PARTS=host,path,query `
  -e LM_TABLE_SIZE=400000 `
  -e CALIBRATE=1 -e CALIBRATE_METHOD=sigmoid `
  -e PROGRESS_EVERY=25000 `
  -e RF_VERBOSE=1 `
  backend sh -lc "cd /app/models && python train.py"
 ```

 #### Option B — macOS/Linux (bash/zsh)
 ```bash
docker compose run --rm \
  -e SAMPLE_SIZE=0 \
  -e USE_LM=1 -e USE_TRIGRAM=1 \
  -e TRIGRAM_BUCKETS=1024 \
  -e LM_PARTS=host,path,query \
  -e LM_TABLE_SIZE=400000 \
  -e CALIBRATE=1 -e CALIBRATE_METHOD=sigmoid \
  -e PROGRESS_EVERY=25000 \
  -e RF_VERBOSE=1 \
  backend sh -lc "cd /app/models && python train.py"
 ```

After training, restart backend + worker (recommended):
 ```bash
docker compose restart backend worker
 ```

 ### 4.3 Verify the Model File Exists
 #### Windows (PowerShell)
 ```bash
Test-Path .\backend\models\ml_model.pkl
 ```

 #### macOS/Linux
 ```bash
ls -l backend/models/ml_model.pkl
 ```

---

 ## 5) Run Inference (UI)
1) Open the UI: 
 ```
http://localhost:8080
 ```
2) Paste a URL into the input field
3) Click **Analyze**
4) The request is queued via Redis and processed by Celery worker(s)
5) The UI displays the prediction result

---

 ## 6) Stop / Clean
Stop services (keeps local files in your project folder):
 ```bash
docker compose down
 ```

Remove containers + volumes:
 ```bash
docker compose down -v
 ```

---

 ## 7) Troubleshooting 

 ### 7.1 "docker-compose.yaml not found" / Wrong directory
You are not in the project root.

Fix:
- `cd` into the folder that contains `docker-compose.yaml`
- run `dir` (Windows) or `ls` (macOS/Linux) and verify you see:
  - `docker-compose.yaml`, `backend/`, `worker/`, `frontend/`

 ### 7.2 Docker Desktop not running
Symptoms:
- compose commands fail or containers do not start

Fix:
- Start Docker Desktop
- retry:
 ```bash
docker compose up -d --build
 ```

 ### 7.3 Ports already in use (8000 / 8080 / 6379)
Symptoms:
- backend/frontend/redis fails to start due to port binding

Fix:
- Stop the conflicting service OR change the port mapping in `docker-compose.yaml`.

Check running containers:
 ```bash
docker compose ps
 ```

 ### 7.4 UI loads but never returns a result
Fix checklist:
1) verify all services are running:
 ```bash
docker compose ps
 ```
2) inspect logs:
 ```bash
docker compose logs --tail=200 backend
docker compose logs --tail=200 worker
docker compose logs --tail=200 redis
 ```

 ### 7.5 "Model Not Found" / prediction fails
Cause: training has not been executed yet.

Fix:
1) run training (Section 4.2 FULL recommended)
2) restart backend + worker:
 ```bash
docker compose restart backend worker
 ```

 ### 7.6 Clean rebuild if something is stuck
Try a full clean rebuild:
 ```bash
docker compose down
docker compose up -d --build
 ```

If you want to remove volumes too:
 ```bash
docker compose down -v
docker compose up -d --build
 ```

 ### 7.7 Quick health checks (optional)
Redis ping:
 ```bash
docker compose exec redis redis-cli ping
 ```

Check running services:
 ```bash
docker compose ps
 ```

---

 ## 8) Quick Flow 
 ```bash
docker compose up -d --build
docker compose run --rm backend sh -lc "cd /app/models && python train.py"
docker compose restart backend worker
 ```

Then open:
 ```
http://localhost:8080

 ```
