from sqlalchemy import Column, Integer, String, DateTime, Text, Float
from sqlalchemy.sql import func
from database import Base
from datetime import datetime

class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    url = Column(String, unique=True, index=True)
    status = Column(String, default="Pendiente")
    last_scan = Column(DateTime(timezone=True), server_default=func.now())
    waf_detected = Column(String, default="No verificado")

class Finding(Base):
    __tablename__ = "findings"

    id          = Column(Integer, primary_key=True, index=True)
    target_id   = Column(Integer, nullable=False, index=True)
    module      = Column(String(50), nullable=False)   # zap | nikto | headers | certs | whatweb | waf
    severity    = Column(String(20))                   # critical | high | medium | low | info
    title       = Column(String, nullable=False)
    description = Column(Text)
    extra       = Column(Text)                         # JSON serializado
    confidence  = Column(Float, nullable=True)          # 0.0–1.0; retroalimentado por attack_results
    scan_date   = Column(DateTime(timezone=True), server_default=func.now())

class Schedule(Base):
    __tablename__ = "schedules"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, nullable=True)          # legacy, kept for compat
    target_ids = Column(String, nullable=True)          # JSON array: "[1, 2, 3]"
    module = Column(String)
    scheduled_at = Column(String)      # ISO datetime: "2026-06-01T09:00:00"
    repeat = Column(String, default="once")  # once | daily | weekly | monthly
    last_run = Column(String, nullable=True)            # "2026-06-02T09:30" — anti-duplicate
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class VectorRun(Base):
    __tablename__ = "vector_runs"

    id             = Column(Integer, primary_key=True, index=True)
    target_id      = Column(Integer, nullable=False, index=True)
    vector_name    = Column(String, nullable=False)
    vector_titulo  = Column(String, nullable=True)
    vector_json    = Column(Text, nullable=True)
    mode           = Column(String, nullable=False)     # "quick" | "full"
    instructions   = Column(Text, nullable=True)
    status         = Column(String, default="pending")  # pending|running|completed|failed
    estado         = Column(String, nullable=True)      # explotable|no_explotable|inconcluso
    resumen        = Column(Text, nullable=True)
    evidencia_tecnica   = Column(Text, nullable=True)
    impacto_negocio     = Column(Text, nullable=True)
    comando_clave       = Column(Text, nullable=True)
    recomendacion       = Column(Text, nullable=True)
    iterations     = Column(Integer, default=0)
    started_at     = Column(DateTime(timezone=True), nullable=True)
    completed_at   = Column(DateTime(timezone=True), nullable=True)
    created_at     = Column(DateTime(timezone=True), server_default=func.now())


class AiAttackPlan(Base):
    __tablename__ = "ai_attack_plans"

    id           = Column(Integer, primary_key=True, index=True)
    target_id    = Column(Integer, nullable=False, index=True)
    plan_json    = Column(Text, nullable=False)   # full JSON returned by AI
    vector_count = Column(Integer, default=0)
    generated_at = Column(DateTime(timezone=True), server_default=func.now())


class Report(Base):
    __tablename__ = "reports"

    id                 = Column(Integer, primary_key=True, index=True)
    scope              = Column(String(10), nullable=False)   # "single" | "all"
    target_ids         = Column(Text, nullable=True)          # JSON array "[1,2]" or null when scope=all
    report_type        = Column(String(20), nullable=False)   # "executive" | "technical" | "compliance"
    title              = Column(String(255))
    status             = Column(String(20), default="ready")  # pending | generating | ready | error
    findings_snapshot  = Column(Text)                         # JSON snapshot of findings at generation time
    ai_content         = Column(Text)                         # JSON: slots for AI-generated sections (filled by agent)
    created_at         = Column(DateTime(timezone=True), server_default=func.now())
    generated_at       = Column(DateTime(timezone=True), nullable=True)