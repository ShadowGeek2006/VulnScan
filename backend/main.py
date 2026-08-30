"""
VulnScope API entrypoint.

Run with: uvicorn backend.main:app --reload
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.scan import router as scan_router

app = FastAPI(
    title="VulnScope",
    description="Website vulnerability assessment and scoring API",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten before production
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(scan_router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "vulnscope-api"}


@app.get("/")
def root():
    return {
        "message": "VulnScope API — see /docs for the interactive API explorer",
    }
