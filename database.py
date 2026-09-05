import logging
import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from models import Base

logger = logging.getLogger(__name__)

DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/osint_db")

engine = create_async_engine(
    DATABASE_URL,
    echo=False,
    pool_size=20,          # Держим 20 постоянных открытых подключений к Postgres
    max_overflow=10,       # Дополнительно до 10 подключений при пиковых нагрузках
    pool_timeout=30,       # Ждать освобождения подключения не более 30 сек
    pool_recycle=1800,     # Пересоздавать соединения каждые 30 мин, чтобы избежать разрывов
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

async def init_models() -> None:
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        logger.critical("Failed to initialize database models", exc_info=True)
        raise

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error("Database session error", exc_info=True)
            raise
        finally:
            await session.close()