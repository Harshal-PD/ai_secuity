from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from hackersec.db.store import init_db
from hackersec.api.routes.upload import router as upload_router
from hackersec.api.routes.results import router as results_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="HackerSec",
    description="AI-Driven Security Code Review & Vulnerability Analysis",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload_router)
app.include_router(results_router)


@app.get("/health")
def health():
    return {"status": "ok", "service": "hackersec"}
