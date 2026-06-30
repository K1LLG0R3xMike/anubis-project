# Revisión Arquitectónica — Anubis Attack

Documento de observaciones sobre la propuesta de arquitectura del módulo de explotación de Anubis (fases Attack Planner → Exploit Execution → Evidence → Report).

El objetivo no es bloquear el diseño, sino dejar por escrito qué partes están sólidas, dónde el plan se vuelve optimista y qué piezas faltan antes de pasar a implementación seria.

---

## Resumen ejecutivo

| Aspecto | Estado | Notas |
|---|---|---|
| Flujo general (findings → plan → ejecución → evidencia → reporte) | ✅ Sólido | Patrón correcto, alineado con herramientas del sector |
| Diseño de tablas y endpoints | ✅ Sólido | `attack_runs` / `attack_results` bien normalizadas |
| Orquestación con Celery + WebSocket | ✅ Sólido | Elección correcta frente a polling |
| Cronograma de 5 semanas | ⚠️ Irreal para producción | Aceptable como PoC, no como herramienta confiable |
| Priorización por IA (`ai_prioritize`) | ⚠️ Handwaveada | Necesita schema estricto o heurística determinista |
| Cálculo automático de CVSS | ⚠️ Engañoso | Sin contexto del target, el score es ruido |
| Mapeo `FINDING_TO_ATTACK_MAP` 1:N | ⚠️ Simplista | La realidad es N:M con contexto |
| Validación de scope/autorización | ❌ Ausente | Imprescindible antes de cualquier target real |
| Niveles de intrusividad configurables | ❌ Ausente | Necesario para diferenciar verificación vs explotación |
| Manejo de falsos positivos del scan | ❌ Ausente | El attack planner debería filtrar por confianza |
| Modelo de dependencias entre vectores | ❌ Ausente | Lista lineal se queda corta; hace falta DAG |

---

## 1. Lo que está bien planteado

### 1.1 Flujo general
El pipeline `findings → plan → ejecución → evidencia → reporte` es el patrón correcto y el que usan herramientas serias del sector. Separar planificación de ejecución permite revisar el plan antes de lanzarlo, abortar a mitad, reanudar, y auditar.

### 1.2 Reutilización del patrón de scan
Que los módulos de `attack_scripts/` espejen los de `scripts/` minimiza el coste cognitivo y permite que el orquestador trate ambos de forma uniforme. Buena decisión.

### 1.3 Modelo de datos
- `attack_runs` con `plan_json` separada de `attack_results` está bien normalizada.
- El campo `status` con estados `planned/running/completed/aborted` cubre el ciclo de vida.
- `evidence_path` como ruta y no como blob es correcto para archivos pesados (screenshots, dumps).

### 1.4 Telemetría en tiempo real
WebSocket para el terminal en vivo es la elección correcta frente a polling. La integración con Redis pub/sub desde la tarea Celery es el patrón estándar.

### 1.5 Orden de implementación
Empezar por `header_exploits.py` como prueba de extremo a extremo es exactamente el orden correcto: valida toda la cadena sin meterse aún en SQLMap ni Playwright.

---

## 2. Donde el plan se vuelve optimista

### 2.1 Cronograma
Las 5 semanas son irreales si se pretende que los módulos funcionen de verdad y no sean PoCs frágiles. Cada módulo de explotación es esencialmente un mini-proyecto:

- **SQLMap** lleva más de una década madurando. Envolverlo bien implica parsear su salida, detectar falsos positivos, manejar timeouts, gestionar tamper scripts según el WAF detectado, etc.
- **Hydra/Patator** requieren listas de credenciales contextuales y manejo de bloqueos.
- **Playwright** para capturar evidencia de XSS añade su propia complejidad (lanzar navegador, esperar dispatcher, capturar antes de redirect, etc.).

Para un PoC end-to-end de los 5 módulos básicos sí, 5 semanas. Para algo confiable, multiplicar por 3.

### 2.2 Priorización por IA
La función `ai_prioritize()` está handwaveada. Gemini sin un prompt muy disciplinado va a generar órdenes inconsistentes entre runs sobre los mismos findings.

**Recomendación**: si se usa IA aquí, atar el output a un schema estricto (Pydantic) y, en paralelo, evaluar si una heurística determinista no da el 80% del valor sin el coste:

```
score = CVSS_base × exposicion_score × (1 + presencia_PoC_publico) × confianza_finding
```

Y reservar la IA para casos de empate o para sugerir combinaciones de vectores que la heurística no captura.

### 2.3 Cálculo automático de CVSS
El `cvss_score` calculado por módulo es engañoso. CVSS no se calcula bien sin contexto:

- El mismo SQLi en un endpoint de búsqueda interna y en `/admin` da scores muy distintos.
- El impacto depende de qué datos hay detrás, no solo de la vulnerabilidad.

**Recomendación**: guardar las métricas CVSS por separado (AV, AC, PR, UI, S, C, I, A) y calcular el score en una capa de reporting con override manual posible.

---

## 3. Lo que falta y es crítico

### 3.1 Validación de scope / autorización
Un framework que ejecuta SQLMap, Hydra y exploits CVE necesita una compuerta dura al inicio de cada run que verifique que el target está autorizado.

**Propuesta de modelo**:

```
authorized_targets
├── id (PK)
├── domain_pattern   -- e.g. "*.empresa.com" o IP/CIDR
├── valid_from
├── valid_until
├── authorized_by    -- referencia al usuario que firmó
├── scope_document   -- ruta al PDF/contrato
└── allowed_modules  -- lista blanca de módulos permitidos
```

Antes de ejecutar cualquier `attack_run`, el orquestador valida que el target del run cae dentro de al menos un registro vigente. Sin esto no es solo riesgo legal: es riesgo de que un día se meta mal una URL y la cadena automatizada haga daño real.

### 3.2 Niveles de intrusividad
Hay diferencia enorme entre "verifica que el SQLi existe extrayendo `@@version`" y "extrae todas las tablas". El plan debería tener un campo por vector:

```python
intrusiveness: Literal["passive", "active", "exploitive"]
```

- **passive**: solo lectura, sin modificar estado del target
- **active**: envía payloads pero no extrae datos sensibles
- **exploitive**: extracción/escalada completa

Cada módulo debe respetar el nivel solicitado y abortar si el plan pide algo fuera de su capacidad.

### 3.3 Manejo de falsos positivos heredados del scan
ZAP marca cosas como SQLi `medium` que no lo son. Si el attack planner consume findings ciegamente, va a gastar tiempo de ejecución persiguiendo fantasmas.

**Recomendación**:
- Añadir un campo `confidence` (0.0 – 1.0) a la tabla `findings`.
- El planner aplica un umbral configurable por vector (e.g. SQLMap solo se lanza con `confidence >= 0.6`).
- Resultado del attack alimenta de vuelta la confianza del finding: si el ataque confirma, sube; si falla, baja.

### 3.4 Mapeo de findings a vectores
El `FINDING_TO_ATTACK_MAP` es 1:N pero la realidad es N:M con contexto. Ejemplos:

- "TLS débil + HSTS ausente" habilita SSL stripping de forma cualitativamente distinta que cada uno por separado.
- "WordPress 5.8 + endpoint `/wp-admin` expuesto + login form sin rate limit" combinados dan un vector de bruteforce de alto impacto.

**Recomendación**: modelar el planner como un sistema de reglas con `condiciones` (lista de findings requeridos) → `vector`, no como un diccionario 1:N.

### 3.5 Plan como DAG, no como lista
`attack_plan` como lista priorizada se queda corto. Vectores tienen dependencias:

- El resultado de `cve_exploiter` puede habilitar nuevos vectores post-explotación.
- Un `auth_bruteforce` exitoso desbloquea ataques que requieren sesión.
- IDOR encontrado en `/api/v1/users/{id}` habilita enumeración masiva.

**Recomendación**: modelar el plan como DAG desde el inicio. Cada nodo declara `requires` (nodos cuya ejecución exitosa habilita este) y `provides` (capacidades que entrega, e.g. `authenticated_session`, `db_credentials`). Si se arranca con lista lineal, toca refactorizar al mes 2.

### 3.6 Auditoría y trazabilidad
No se menciona logging persistente más allá de los `attack_results`. Para una herramienta ofensiva esto es imprescindible:

- Log inmutable (append-only) de cada acción ejecutada, con timestamp, target, módulo, payload exacto.
- Asociación clara a la autorización vigente en el momento de la ejecución.
- Retención mínima alineada con los requisitos del cliente / contrato.

---

## 4. Comentarios adicionales sobre la propuesta

### 4.1 Sobre el WebSocket
La implementación esbozada en `main.py` está bien. Recordar:
- Autenticar el WebSocket (no dejar `/ws/attack/{run_id}` abierto).
- Manejar reconexiones: el cliente puede caerse y volver; el backend debe poder reenviar logs desde un offset.
- Buffer en Redis con TTL para no acumular logs eternos.

### 4.2 Sobre la captura de evidencia
Playwright es buena elección, pero:
- Headless puede ser detectado por algunos targets; tener modo `headed` opcional.
- Las screenshots deben capturarse antes de cualquier redirect post-exploit.
- Guardar también el HAR (HTTP Archive) además del request/response, para reproducibilidad completa.

### 4.3 Sobre la abortabilidad
El check `if run.status == "aborted": break` en la tarea Celery solo aborta entre vectores. Vectores largos (SQLMap puede tardar horas) seguirán corriendo. Considerar:
- Comunicar el abort a los subprocesos vía signal o flag compartido en Redis.
- Timeout por vector configurable en el plan.

---

## 5. Veredicto

**Como arquitectura para un proyecto de portfolio / internship con ambición seria**: viable y bien pensada en lo estructural. El diseño tiene los huesos correctos.

**Como herramienta para uso más allá de labs y CTFs**: necesita las piezas de scope, intrusividad, auditoría y manejo de falsos positivos antes de cualquier despliegue real. Y un cronograma honesto: 5 semanas dan para un PoC funcional sobre un target controlado; no para una herramienta lista para clientes.

**Siguiente paso recomendado**: antes de empezar a codear módulos de explotación, cerrar dos cosas en papel:

1. El **schema del `attack_plan`** (DAG + intrusividad + confianza) como contrato firme entre planner y módulos.
2. El **modelo de autorización** y dónde se enchufa la compuerta en el flujo de ejecución.

Con esas dos piezas claras, la Semana 1 sigue siendo el mismo `header_exploits.py` que propone el plan original, pero ya sobre cimientos que no obligan a refactorizar al mes.

---

*Documento generado a partir de la revisión del diseño `Anubis_Attack — Arquitectura y Fases`.*
