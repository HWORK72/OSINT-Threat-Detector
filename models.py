from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Column, Integer, String, DateTime, JSON
from sqlalchemy.orm import declarative_base

Base: Any = declarative_base()

class ScanHistory(Base):
    __tablename__ = "scan_history"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True, nullable=False)
    target_type = Column(String, nullable=False)
    threat_score = Column(Integer, default=0)
    results_payload = Column(JSON, nullable=False)
    # Отрезаем tzinfo перед отправкой в базу данных
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None))