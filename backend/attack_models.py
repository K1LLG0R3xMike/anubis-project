from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, Float
from sqlalchemy.sql import func
from database import Base


class AuthorizedTarget(Base):
    """
    Registro de autorización para un dominio o IP.
    Todo attack_run debe estar cubierto por un registro vigente antes de ejecutarse.
    """
    __tablename__ = "authorized_targets"

    id                    = Column(Integer, primary_key=True, index=True)
    domain_pattern        = Column(String(255), nullable=False)    # "*.empresa.com" | "192.168.1.0/24" | "host.local"
    valid_from            = Column(DateTime(timezone=True), nullable=False)
    valid_until           = Column(DateTime(timezone=True), nullable=False)
    authorized_by         = Column(String(100), nullable=False)    # usuario que firmó la autorización
    scope_document        = Column(String(512), nullable=True)     # ruta al PDF/contrato de alcance
    allowed_modules       = Column(Text, nullable=True)            # JSON array: ["sqli","header_exploits"] — null = todos
    allowed_intrusiveness = Column(String(20), default="active")   # passive | active | exploitive
    notes                 = Column(Text, nullable=True)
    created_at            = Column(DateTime(timezone=True), server_default=func.now())


class AttackRun(Base):
    """
    Una ejecución de un plan de ataque contra un target.
    plan_json almacena el AttackPlan completo (DAG) serializado como JSON.
    El campo abort_requested permite señalizar un abort entre nodos.
    """
    __tablename__ = "attack_runs"

    id                    = Column(Integer, primary_key=True, index=True)
    target_id             = Column(Integer, nullable=False, index=True)   # FK → targets
    authorized_target_id  = Column(Integer, nullable=True)                # FK → authorized_targets
    plan_json             = Column(Text, nullable=False)                  # AttackPlan serializado
    status                = Column(String(20), default="planned")         # planned|running|completed|aborted|failed
    intrusiveness         = Column(String(20), default="active")          # máximo nivel permitido en este run
    abort_requested       = Column(Boolean, default=False)                # señal de abort cooperativo
    created_by            = Column(String(100), nullable=True)
    started_at            = Column(DateTime(timezone=True), nullable=True)
    completed_at          = Column(DateTime(timezone=True), nullable=True)
    created_at            = Column(DateTime(timezone=True), server_default=func.now())


class AttackResult(Base):
    """
    Resultado de ejecutar un nodo (vector) dentro de un attack_run.
    confidence_delta retroalimenta la confianza del finding origen en la tabla findings.
    """
    __tablename__ = "attack_results"

    id                = Column(Integer, primary_key=True, index=True)
    run_id            = Column(Integer, nullable=False, index=True)    # FK → attack_runs
    node_id           = Column(String(100), nullable=False)            # coincide con node.id en el DAG
    vector_type       = Column(String(50), nullable=False)             # "header_exploits" | "sqli" | ...
    status            = Column(String(20), default="planned")          # planned|running|completed|failed|aborted|skipped
    output_json       = Column(Text, nullable=True)                    # salida estructurada del módulo
    evidence_path     = Column(String(512), nullable=True)             # ruta a screenshot / pcap / dump
    confirmed_finding = Column(Boolean, nullable=True)                 # ¿confirmó la vulnerabilidad?
    confidence_delta  = Column(Float, default=0.0)                     # ajuste a findings.confidence
    error_message     = Column(Text, nullable=True)
    started_at        = Column(DateTime(timezone=True), nullable=True)
    completed_at      = Column(DateTime(timezone=True), nullable=True)
    created_at        = Column(DateTime(timezone=True), server_default=func.now())
