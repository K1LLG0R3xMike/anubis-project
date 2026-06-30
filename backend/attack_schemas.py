"""
Pydantic schemas para el plan de ataque DAG de Anubis Attack.

Un AttackPlan es un grafo acíclico dirigido (DAG) donde:
  - Cada nodo es un AttackNode que representa un vector a ejecutar.
  - requires_nodes: IDs de nodos que deben completarse antes de que este pueda correr.
  - requires_capabilities: capacidades (e.g. "authenticated_session") que deben
    estar disponibles (provistas por algún nodo completado) antes de correr.
  - provides: capacidades que este nodo desbloquea si confirma el finding.

La separación entre requires_nodes (dependencia estructural) y
requires_capabilities (dependencia funcional) permite modelar cadenas
post-explotación sin acoplar los IDs de nodo directamente.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field

# ─────────────────────────────────────────────
# Tipos base
# ─────────────────────────────────────────────

Intrusiveness = Literal["passive", "active", "exploitive"]
NodeStatus = Literal["planned", "running", "completed", "failed", "aborted", "skipped"]

INTRUSIVENESS_RANK: Dict[str, int] = {
    "passive":   0,
    "active":    1,
    "exploitive": 2,
}


# ─────────────────────────────────────────────
# Nodo del DAG
# ─────────────────────────────────────────────

class AttackNode(BaseModel):
    # Identidad
    id: str
    vector_type: str
    target_url: str

    # Origen
    finding_id: Optional[int] = None
    finding_title: str
    finding_severity: str = "medium"
    finding_confidence: float = 0.5

    # Control de ejecución
    intrusiveness: Intrusiveness
    requires_nodes: List[str] = Field(default_factory=list)
    requires_capabilities: List[str] = Field(default_factory=list)
    provides: List[str] = Field(default_factory=list)
    confidence_threshold: float = 0.5
    timeout_seconds: int = 300
    params: dict = Field(default_factory=dict)

    # Estado en tiempo de ejecución
    status: NodeStatus = "planned"
    priority_score: float = 0.0


# ─────────────────────────────────────────────
# Plan completo (DAG)
# ─────────────────────────────────────────────

class AttackPlan(BaseModel):
    nodes: List[AttackNode] = Field(default_factory=list)
    target_url: str
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def get_node(self, node_id: str) -> Optional[AttackNode]:
        return next((n for n in self.nodes if n.id == node_id), None)

    def get_executable_nodes(
        self,
        completed_ids: set,
        failed_ids: set,
        available_capabilities: set,
    ) -> List[AttackNode]:
        """
        Devuelve nodos listos para ejecutar:
          - status == "planned"
          - todos sus requires_nodes están en completed_ids
          - ningún requires_node está en failed_ids
          - todas sus requires_capabilities están en available_capabilities
        El resultado viene ordenado de mayor a menor priority_score.
        """
        executable = []
        for node in self.nodes:
            if node.status != "planned":
                continue
            if any(r in failed_ids for r in node.requires_nodes):
                continue
            if not all(r in completed_ids for r in node.requires_nodes):
                continue
            if not all(c in available_capabilities for c in node.requires_capabilities):
                continue
            executable.append(node)
        return sorted(executable, key=lambda n: -n.priority_score)

    def has_pending_nodes(self) -> bool:
        return any(n.status == "planned" for n in self.nodes)

    def summary(self) -> dict:
        counts: Dict[str, int] = {}
        for n in self.nodes:
            counts[n.status] = counts.get(n.status, 0) + 1
        return counts


# ─────────────────────────────────────────────
# Schemas de API
# ─────────────────────────────────────────────

class AttackRunCreate(BaseModel):
    target_id: int
    intrusiveness: Intrusiveness = "active"
    authorized_target_id: Optional[int] = None
    confidence_threshold: float = 0.5
    finding_ids: Optional[List[int]] = None  # None = usar todos los findings del target


class AttackRunResponse(BaseModel):
    id: int
    target_id: int
    status: str
    intrusiveness: str
    node_count: int
    plan_summary: dict
    created_at: str

    class Config:
        from_attributes = True


class AuthorizedTargetCreate(BaseModel):
    domain_pattern: str
    valid_from: datetime
    valid_until: datetime
    authorized_by: str
    scope_document: Optional[str] = None
    allowed_modules: Optional[List[str]] = None
    allowed_intrusiveness: Intrusiveness = "active"
    notes: Optional[str] = None


class AuthorizedTargetResponse(BaseModel):
    id: int
    domain_pattern: str
    valid_from: datetime
    valid_until: datetime
    authorized_by: str
    allowed_intrusiveness: str
    is_active: bool
    notes: Optional[str] = None

    class Config:
        from_attributes = True
