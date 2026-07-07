import os
import time
import requests
import json
import sys
import subprocess
import psycopg2
import redis
from urllib.parse import quote
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db_findings import save_findings

# --- CONFIGURACIÓN INTEGRADA ---
ZAP_PATH = "zaproxy"
ZAP_API_URL = "http://127.0.0.1:9090"
API_KEY = "b57r80eafoogrcivehpv83qgp0"
ZAP_SCAN_POLICY = "Default Policy"

# Rutas estándar de tu proyecto
REPORTS_DIR = "/home/anubis/AnubisProject/reports/zap" # Carpeta para los JSON de ZAP
TARGETS_FILE = "/home/anubis/AnubisProject/reports/sitios.txt"
DATABASE_URL = "postgresql://admin:Malware2030$@localhost:5432/ciber_db"

os.makedirs(REPORTS_DIR, exist_ok=True)

# Mismo Redis (db=1) que usa main.py/tasks.py para locks de deduplicación.
# Acá sirve para serializar la fase de active scan por etapas: dos escaneos
# de ZAP corriendo a la vez (la cola heavy permite concurrencia 2) pisarían
# la política de reglas compartida si ambos la tocan al mismo tiempo.
_zap_redis = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
ZAP_POLICY_LOCK_KEY = "anubis:zap_policy_lock"

# Grupos de reglas de active scan por palabra clave en el nombre — no se cablean
# IDs porque cambian entre versiones/addons de ZAP. Cada grupo corre como una
# pasada separada: reduce el volumen de payloads "sospechosos" enviados en
# ráfaga, dándole a ZAP mejor chance de completar comparaciones diferenciales
# (ej. SQL Injection boolean-based) antes de que un WAF empiece a bloquear o
# limitar por volumen. El precio es que el escaneo completo tarda más — cada
# etapa vuelve a recorrer el sitio con menos reglas activas.
SCAN_STAGE_KEYWORDS = [
    ("sqli",      ["sql injection"]),
    ("xss",       ["cross site scripting", "xss"]),
    ("cmd_rce",   ["command injection", "code injection", "shell", "remote code execution",
                    "template injection", "log4shell", "spring4shell", "react2shell"]),
    ("traversal", ["path traversal", "file inclusion", "external entity", "xxe",
                    "cloud metadata", "xpath injection", "xslt injection"]),
    ("misc_inject", ["injection", "padding oracle", "soap"]),
]
STAGE_PAUSE_SECONDS = 15  # respiro entre etapas para no sumar ráfagas consecutivas

# La regla "Cross Site Scripting (DOM Based)" es la única de las 53 que abre
# un Firefox real vía Selenium para renderizar la página. Comprobado en vivo:
# incluso limitando la concurrencia a 2 hilos se cuelga después de ~15-20 min
# (17.000+ requests sin avanzar, ~60 procesos Firefox/GeckoDriver acumulados
# sin liberarse) — la misma inestabilidad de Selenium/GeckoDriver que ya
# habíamos visto con el daemon de ZAP. Las otras reglas de XSS (Reflected,
# Persistent, Persistent-Prime/Spider) no dependen de navegador y cubren la
# mayoría de casos reales, así que se excluye del ciclo automático. Sigue
# disponible para correrla puntual/manual vía la API de ZAP si hace falta.
EXCLUDED_SCANNER_KEYWORDS = ["dom based"]

def _group_scanners_into_stages(scanners):
    """dict: nombre_de_etapa -> lista de scanner ids. 'resto' agrupa todo lo
    que no matcheó ninguna keyword (headers, info leaks, fuzzing, etc.). Los
    scanners en EXCLUDED_SCANNER_KEYWORDS quedan fuera de todas las etapas."""
    stages = {name: [] for name, _ in SCAN_STAGE_KEYWORDS}
    stages["resto"] = []
    for s in scanners:
        name_lower = s.get('name', '').lower()
        if any(k in name_lower for k in EXCLUDED_SCANNER_KEYWORDS):
            continue
        for stage_name, keywords in SCAN_STAGE_KEYWORDS:
            if any(k in name_lower for k in keywords):
                stages[stage_name].append(s['id'])
                break
        else:
            stages["resto"].append(s['id'])
    return stages

def update_db_status(url, message):
    """Actualiza el estado en la base de datos para el Dashboard"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("UPDATE targets SET status = %s WHERE url = %s", (message, url))
        conn.commit()
        cur.close()
        conn.close()
        print(f"[#] DB Status: {url} -> {message}")
    except Exception as e:
        print(f"[!] Error DB: {e}")

def get_target_name_from_db(url):
    """Obtiene el nombre del objetivo para nombrar el archivo JSON"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("SELECT name FROM targets WHERE url = %s", (url,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        return result[0] if result else url.split("//")[-1].replace("/", "_")
    except:
        return url.split("//")[-1].replace("/", "_")

def start_zap():
    """Levanta ZAP si no está activo"""
    try:
        requests.get(ZAP_API_URL, timeout=5)
        print("[+] ZAP ya está en ejecución.")
    except:
        print("[!] ZAP no detectado. Levantando instancia...")
        subprocess.Popen([
            ZAP_PATH, "-daemon", "-port", "9090", 
            "-config", f"api.key={API_KEY}",
            "-config", "api.addrs.addr.name=127.0.0.1",
            "-config", "api.addrs.addr.dotNetMask=24"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(20):
            try:
                requests.get(ZAP_API_URL, timeout=2)
                print("[+] ZAP conectado.")
                return
            except: time.sleep(3)
        print("[-] Error: No se pudo iniciar ZAP.")
        sys.exit(1)

def wait_for_progress(url, component, scan_id=None):
    while True:
        params = {'apikey': API_KEY}
        if scan_id: params['scanId'] = scan_id
        try:
            r = requests.get(f"{ZAP_API_URL}/JSON/{component}/view/status/", params=params)
            status = r.json().get('status', '100')
            print(f"  [+] {component.upper()}: {status}%")
            update_db_status(url, f"ZAP {component}: {status}%")
            if str(status) == "100": break
        except Exception as e:
            print(f"  [!] {component.upper()}: error polling ({e}), abortando espera.")
            break
        time.sleep(10)

def _extract_evidencia(a):
    """
    Fallback cuando ZAP no captura 'evidence' (string vacío, no ausente):
    algunas reglas activas (Path Traversal, SQL Injection basado en timing/
    errores) no dejan un match literal en la respuesta. El campo real que
    trae la explicación técnica de ZAP es 'other' (no 'otherinfo', que no
    existe en esta API y por eso nunca se usaba). Se prioriza el payload
    real enviado ('attack') junto al parámetro, y la explicación de 'other'
    (ej. condiciones booleanas probadas en una inyección SQL), antes de
    caer al parámetro/URL desnudos. La URL siempre se agrega (no solo como
    fallback) para poder reproducir el hallazgo sin volver a ZAP.
    """
    evidencia = (a.get('evidence') or '').strip()
    attack = (a.get('attack') or '').strip()
    param = (a.get('param') or '').strip()
    other = (a.get('other') or '').strip().replace('\n', ' ')
    url = (a.get('url') or '').strip()

    partes = []
    if evidencia:
        partes.append(evidencia)
    elif attack:
        partes.append(f"Payload: {attack}" + (f" (parámetro: {param})" if param else ""))
    elif param:
        partes.append(f"Parámetro afectado: {param}")

    if url:
        partes.append(f"URL: {url}")
    if other:
        partes.append(other)

    if partes:
        return " | ".join(partes)[:500]
    return "Sin evidencia específica capturada por ZAP"

def run_zap_engine(target_url):
    target_name = get_target_name_from_db(target_url).lower().replace(" ", "_")
    print(f"\n🚀 MOTOR OWASP ZAP: {target_url} ({target_name})")

    # Limitar concurrencia: 4 hilos por host, 1 host a la vez (evita acumulación de Firefox en /tmp)
    requests.get(f"{ZAP_API_URL}/JSON/ascan/action/setOptionThreadPerHost/", params={'apikey': API_KEY, 'Integer': 6})
    requests.get(f"{ZAP_API_URL}/JSON/ascan/action/setOptionHostPerScan/", params={'apikey': API_KEY, 'Integer': 1})

    # 1. Spider
    update_db_status(target_url, "ZAP: Iniciando Spider...")
    s_data = requests.get(f"{ZAP_API_URL}/JSON/spider/action/scan/", params={'apikey': API_KEY, 'url': target_url}).json()
    wait_for_progress(target_url, "spider", s_data.get('scan'))

    # 2. Active Scan por etapas (lock global: ver ZAP_POLICY_LOCK_KEY)
    lock = _zap_redis.lock(ZAP_POLICY_LOCK_KEY, timeout=1800, blocking_timeout=1800)
    if not lock.acquire():
        update_db_status(target_url, "ZAP: Error - no se pudo reservar la política de ZAP")
        raise RuntimeError("No se pudo adquirir el lock de política de ZAP (otro escaneo lo tuvo reservado 30 min)")
    try:
        scanners = requests.get(f"{ZAP_API_URL}/JSON/ascan/view/scanners/",
                                 params={'apikey': API_KEY, 'scanPolicyName': ZAP_SCAN_POLICY}).json().get('scanners', [])
        stages = _group_scanners_into_stages(scanners)
        stage_order = [name for name, _ in SCAN_STAGE_KEYWORDS] + ["resto"]

        for i, stage_name in enumerate(stage_order):
            ids = stages.get(stage_name) or []
            if not ids:
                continue
            update_db_status(target_url, f"ZAP: Atacando ({stage_name}, {len(ids)} regla(s))...")
            requests.get(f"{ZAP_API_URL}/JSON/ascan/action/disableAllScanners/",
                         params={'apikey': API_KEY, 'scanPolicyName': ZAP_SCAN_POLICY})
            requests.get(f"{ZAP_API_URL}/JSON/ascan/action/enableScanners/",
                         params={'apikey': API_KEY, 'ids': ','.join(ids), 'scanPolicyName': ZAP_SCAN_POLICY})

            a_data = requests.get(f"{ZAP_API_URL}/JSON/ascan/action/scan/",
                                   params={'apikey': API_KEY, 'url': target_url, 'recurse': 'true'}).json()
            wait_for_progress(target_url, "ascan", a_data.get('scan'))

            if i < len(stage_order) - 1:
                time.sleep(STAGE_PAUSE_SECONDS)
    finally:
        # Restaurar la política completa siempre, incluso si una etapa falló —
        # así el siguiente escaneo (o alguien usando la UI de ZAP directamente)
        # no hereda una política a medio acotar.
        requests.get(f"{ZAP_API_URL}/JSON/ascan/action/enableAllScanners/",
                     params={'apikey': API_KEY, 'scanPolicyName': ZAP_SCAN_POLICY})
        lock.release()

    # 3. Extraer Alertas (Vulnerabilidad, Evidencia, Severidad, ID OWASP)
    alerts = requests.get(f"{ZAP_API_URL}/JSON/core/view/alerts/", params={'apikey': API_KEY, 'baseurl': target_url}).json().get('alerts', [])
    
    vulnerabilities = []
    seen = set()
    for a in alerts:
        key = f"{a['alert']}-{a['risk']}-{a.get('param', '')}"
        if key not in seen:
            owasp_id = "N/A"
            for t in a.get('tags', {}).keys():
                if "OWASP_2021" in t:
                    owasp_id = t.replace("OWASP_2021_", "")
                    break

            vulnerabilities.append({
                "vulnerabilidad": a['alert'],
                "evidencia": _extract_evidencia(a),
                "severidad": a['risk'],
                "owasp_id": owasp_id
            })
            seen.add(key)

    # 4. Guardar resultado con formato estándar
    output_file = os.path.join(REPORTS_DIR, f"{target_name}.json")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            "target": target_url,
            "vulnerabilities": vulnerabilities,
            "last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }, f, indent=4, ensure_ascii=False)

    zap_findings = []
    for v in vulnerabilities:
        sev = v['severidad'].lower()
        if sev == 'informational': sev = 'info'
        zap_findings.append({
            'severity': sev,
            'title': v['vulnerabilidad'],
            'description': v['evidencia'],
            'extra': {'owasp_id': v['owasp_id']}
        })
    save_findings(target_url, 'zap', zap_findings)

    update_db_status(target_url, "ZAP: Escaneo Finalizado ✅")
    print(f"✅ Reporte guardado en: {output_file}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 owasp.py <url>")
        sys.exit(1)

    target_url = sys.argv[1]
    if not target_url.startswith('http'):
        target_url = 'https://' + target_url

    start_zap()
    try:
        run_zap_engine(target_url)
    except Exception as e:
        print(f"[-] Error en {target_url}: {e}")
        update_db_status(target_url, "ZAP: Error en escaneo")
