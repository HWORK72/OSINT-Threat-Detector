import logging
import os
import json
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Any
from pathlib import Path

import aiohttp
import uvicorn
import redis.asyncio as redis
from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from a2wsgi import ASGIMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from engine import OSINTScanner
from database import init_models, get_db
from models import ScanHistory

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
API_PORT: int = int(os.getenv("API_PORT", "8000"))
REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

BASE_DIR: Path = Path(__file__).resolve().parent
TEMPLATES_DIR: Path = BASE_DIR / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
scanner = OSINTScanner()


class AnalyzeRequest(BaseModel):
    target: str = Field(..., min_length=3, description="IP, Domain or Email to analyze")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger.info("Application starting")
    await init_models()
    app.state.client_session = aiohttp.ClientSession()
    app.state.redis = redis.from_url(REDIS_URL, decode_responses=True)
    yield
    logger.info("Application stopping")
    await app.state.client_session.close()
    await app.state.redis.aclose()


app = FastAPI(title="OSINT Web App", lifespan=lifespan)
wsgi_app = ASGIMiddleware(app)


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request) -> HTMLResponse:
    try:
        return templates.TemplateResponse(
            request=request,
            name="index.html"
        )
    except Exception as e:
        logger.error("Failed to render template", exc_info=True)
        raise


@app.post("/api/analyze")
async def analyze_target(
        payload: AnalyzeRequest,
        request: Request,
        db: AsyncSession = Depends(get_db)
) -> dict[str, Any]:
    try:
        logger.info(f"Received target for analysis: {payload.target}")

        redis_client: redis.Redis = request.app.state.redis
        cache_key = f"osint_cache:{payload.target}"

        cached_data = await redis_client.get(cache_key)

        if cached_data:
            logger.info(f"Returning cached result for {payload.target}")
            analysis_result = json.loads(cached_data)
            is_cached = True
        else:
            session: aiohttp.ClientSession = request.app.state.client_session
            analysis_result = await scanner.analyze(session, payload.target)

            # Сохраняем в кэш только новые результаты
            await redis_client.set(cache_key, json.dumps(analysis_result), ex=3600)
            is_cached = False

        # Запись в историю теперь происходит ВСЕГДА, вне зависимости от источника данных
        db_record = ScanHistory(
            target=analysis_result["target"],
            target_type=analysis_result["type"],
            threat_score=analysis_result["threat_score"],
            results_payload=analysis_result["results"]
        )
        db.add(db_record)

        return {"status": "success", "data": analysis_result, "cached": is_cached}

    except redis.ConnectionError:
        logger.error("Redis connection failed, bypassing cache")
        session = request.app.state.client_session
        analysis_result = await scanner.analyze(session, payload.target)

        db_record = ScanHistory(
            target=analysis_result["target"],
            target_type=analysis_result["type"],
            threat_score=analysis_result["threat_score"],
            results_payload=analysis_result["results"]
        )
        db.add(db_record)
        return {"status": "success", "data": analysis_result, "cached": False}
    except Exception as e:
        logger.error(f"Analysis failed for target: {payload.target}", exc_info=True)
        raise


@app.get("/api/history")
async def get_history(limit: int = 10, db: AsyncSession = Depends(get_db)) -> dict[str, Any]:
    try:
        query = select(ScanHistory).order_by(desc(ScanHistory.created_at)).limit(limit)
        result = await db.execute(query)
        records = result.scalars().all()

        history_data = [
            {
                "id": record.id,
                "target": record.target,
                "type": record.target_type,
                "threat_score": record.threat_score,
                "created_at": record.created_at.isoformat()
            }
            for record in records
        ]
        return {"status": "success", "data": history_data}
    except Exception as e:
        logger.error("Failed to fetch history", exc_info=True)
        raise

if __name__ == "__main__":
    try:
        uvicorn.run("main:app", host=API_HOST, port=API_PORT, reload=True)
    except Exception as e:
        logger.critical("Server crash", exc_info=True)