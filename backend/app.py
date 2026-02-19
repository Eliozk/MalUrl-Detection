# URL-Detector/backend/app.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from celery import Celery
import uuid
import os

app = FastAPI(title="Malicious URL Detector API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

celery_app = Celery(
    "worker",
    broker=os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/0")
)

class URLRequest(BaseModel):
    url: str

@app.get("/")
def health_check():
    return {"status": "online"}

@app.post("/analyze")
async def analyze_url(request: URLRequest):
    job_id = str(uuid.uuid4())
    # --- FIX: Pass task_id=job_id to sync Celery with our Tracking ID ---
    celery_app.send_task(
        "worker.predict_url",
        args=[job_id, request.url],
        task_id=job_id
    )
    return {"job_id": job_id, "status": "processing"}

@app.get("/result/{job_id}")
async def get_result(job_id: str):
    res = celery_app.AsyncResult(job_id)
    if res.ready():
        return {"job_id": job_id, "status": "completed", "result": res.result}
    return {"job_id": job_id, "status": "pending"}