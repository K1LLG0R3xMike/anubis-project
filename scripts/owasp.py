import os
import time
import requests
import json
import sys
import subprocess
import psycopg2
from urllib.parse import quote
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db_findings import save_findings

# --- CONFIGURACIÓN INTEGRADA ---
ZAP_PATH = "zaproxy"
ZAP_API_URL = "http://127.0.0.1:9090"
API_KEY = "b57r80eafoogrcivehpv83qgp0"

# Rutas estándar de tu proyecto
REPORTS_DIR = "/home/anubis/AnubisProject/reports/zap" # Carpeta para los JSON de ZAP
TARGETS_FILE = "/home/anubis/AnubisProject/reports/sitios.txt"
DATABASE_URL = "postgresql://admin:Malware2030$@localhost:5432/ciber_db"

os.makedirs(REPORTS_DIR, exist_ok=True)

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

    # 2. Active Scan
    update_db_status(target_url, "ZAP: Atacando (Active Scan)...")
    a_data = requests.get(f"{ZAP_API_URL}/JSON/ascan/action/scan/", params={'apikey': API_KEY, 'url': target_url, 'recurse': 'true'}).json()
    wait_for_progress(target_url, "ascan", a_data.get('scan'))

    # 3. Extraer Alertas (Vulnerabilidad, Evidencia, Severidad, ID OWASP)
    alerts = requests.get(f"{ZAP_API_URL}/JSON/core/view/alerts/", params={'apikey': API_KEY, 'baseurl': target_url}).json().get('alerts', [])
    
    vulnerabilities = []
    seen = set()
    for a in alerts:
        key = f"{a['alert']}-{a['risk']}"
        if key not in seen:
            owasp_id = "N/A"
            for t in a.get('tags', {}).keys():
                if "OWASP_2021" in t:
                    owasp_id = t.replace("OWASP_2021_", "")
                    break
            
            vulnerabilities.append({
                "vulnerabilidad": a['alert'],
                "evidencia": a.get('evidence', 'N/A')[:200],
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
    start_zap()
    
    if not os.path.exists(TARGETS_FILE):
        print(f"[-] Archivo no encontrado: {TARGETS_FILE}")
        sys.exit(1)

    with open(TARGETS_FILE, 'r') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    for url in urls:
        try:
            run_zap_engine(url)
        except Exception as e:
            print(f"[-] Error en {url}: {e}")
            update_db_status(url, "ZAP: Error en escaneo")
