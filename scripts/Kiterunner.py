# -*- coding: utf-8 -*-
import subprocess
import json
import os
import sys
import re
import psycopg2
 
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db_findings import save_findings
 
# --- CONFIGURACION ---
REPORTS_DIR  = "/home/anubis/AnubisProject/reports/api"
TARGETS_FILE = "/home/anubis/AnubisProject/reports/sitios.txt"
DATABASE_URL = "postgresql://admin:Malware2030$@localhost:5432/ciber_db"
 
KR_WORDLIST  = "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"
KR_TIMEOUT   = '5s'
KR_WORKERS   = 3
INTERESTING_CODES = {200, 201, 204, 301, 302, 401, 403, 405, 422}
 
 
def get_db_conn():
    return psycopg2.connect(DATABASE_URL)
 
 
def get_target_name_from_db(url):
    try:
        conn = get_db_conn()
        cur  = conn.cursor()
        cur.execute("SELECT name FROM targets WHERE url = %s", (url,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        if result:
            name = result[0].lower().strip()
            return re.sub(r'\s+', '_', name)
    except Exception as e:
        print(f"[!] Error consultando nombre: {e}")
    fallback = (url.replace('https://', '')
                   .replace('http://', '')
                   .replace('www.', '')
                   .split('/')[0]
                   .split('.')[0])
    return fallback.lower()
 
 
def update_db(url, endpoints_found, status_summary):
    try:
        conn = get_db_conn()
        cur  = conn.cursor()
        cur.execute(
            "UPDATE targets SET status = %s WHERE url = %s",
            (f"API: {endpoints_found} endpoints - {status_summary}", url)
        )
        conn.commit()
        cur.close()
        conn.close()
        print(f"[#] DB actualizada: {url} -> {endpoints_found} endpoints")
    except Exception as e:
        print(f"[!] Error DB: {e}")
 
 
def strip_ansi(text):
    """Elimina codigos de color ANSI de la salida del terminal."""
    return re.sub(r'\x1b\[[0-9;]*[mGKHF]|\x1b\(B|\r', '', text)
 
 
def parse_kr_output(raw_output):
    """
    Parsea salida de kr brute. Formato de cada linea:
      GET     301 [      0,    0,   0] https://target.com/endpoint -> https://...
      POST    200 [    123,    5,  45] https://target.com/api/login
    """
    raw_output = strip_ansi(raw_output)
    findings = []
    pattern = re.compile(
        r'^\s*\w+\s+(\d{3})\s+\[.*?\]\s+(https?://\S+)',
        re.MULTILINE
    )
    for match in pattern.finditer(raw_output):
        code     = int(match.group(1))
        endpoint = match.group(2).strip().split(' ->')[0].strip()
        if code in INTERESTING_CODES:
            findings.append({'status': code, 'endpoint': endpoint})
    return findings
 
 
def scan_api(url):
    base_url = re.match(r"https?://[0-9a-zA-Z.-]+(:[0-9]+)?", url)
    scan_url = base_url.group(0) if base_url else url
 
    print(f"\n[*] Escaneando APIs en: {scan_url}")
 
    clean_name  = get_target_name_from_db(url)
    output_json = os.path.join(REPORTS_DIR, f"{clean_name}_api.json")
 
    cmd = [
        'kr', 'brute', scan_url,
        '-w', KR_WORDLIST,
        '--timeout', KR_TIMEOUT,
        '-x', str(KR_WORKERS),
        '--fail-status-codes', '404,429',
        '--delay', '300ms',
    ]
 
    try:
        result = subprocess.run(cmd, capture_output=True, text=False, timeout=300)
        stdout = result.stdout.decode('utf-8', errors='replace')
        stderr = result.stderr.decode('utf-8', errors='replace')
        raw    = stdout + stderr
 
        # Debug: mostrar ultimas lineas para verificar resultados
        clean = strip_ansi(raw)
        lineas_resultado = [l for l in clean.splitlines() if re.search(r'\d{3}\s+\[', l)]
        print(f"[*] Lineas con resultados detectadas: {len(lineas_resultado)}")
        for l in lineas_resultado[:10]:
            print(f"    {l.strip()}")
 
        findings = parse_kr_output(raw)
        print(f"[+] Endpoints encontrados: {len(findings)}")
 
        severity_map = {
            200: 'high',   201: 'high',  204: 'medium',
            401: 'medium', 403: 'medium', 405: 'low',
            301: 'info',   302: 'info',  422: 'low',
        }
 
        db_findings = []
        for f in findings:
            sev = severity_map.get(f['status'], 'info')
            db_findings.append({
                'severity'   : sev,
                'title'      : f"API Endpoint [{f['status']}]: {f['endpoint']}",
                'description': f"Endpoint descubierto con status HTTP {f['status']}. URL: {f['endpoint']}",
                'extra'      : {'endpoint': f['endpoint'], 'status_code': f['status']},
            })
 
        report_data = {
            'target'            : scan_url,
            'total_endpoints'   : len(findings),
            'endpoints'         : findings,
            'raw_output_excerpt': clean[:3000],
        }
        os.makedirs(REPORTS_DIR, mode=0o777, exist_ok=True)
        with open(output_json, 'w', encoding='utf-8') as fh:
            json.dump(report_data, fh, indent=2, ensure_ascii=False)
        print(f"[+] Reporte guardado: {output_json}")
 
        codes_summary = ', '.join(sorted({str(f['status']) for f in findings})) or 'ninguno'
 
        if db_findings:
            save_findings(url, 'api', db_findings)
        else:
            save_findings(url, 'api', [{
                'severity'   : 'info',
                'title'      : 'API Scan: Sin endpoints expuestos',
                'description': 'Kiterunner no encontro endpoints de API relevantes.',
                'extra'      : {'total': 0},
            }])
 
        update_db(url, len(findings), codes_summary)
 
    except subprocess.TimeoutExpired:
        print(f"[-] Timeout en {scan_url} - objetivo muy lento.")
        update_db(url, 0, 'timeout')
    except FileNotFoundError:
        print("[!] 'kr' no encontrado. Verifica instalacion en /usr/local/bin/kr")
    except Exception as e:
        print(f"[-] Error inesperado: {e}")
 
 
def main():
    os.makedirs(REPORTS_DIR, mode=0o777, exist_ok=True)
 
    if len(sys.argv) > 1:
        target = sys.argv[1]
        if not target.startswith('http'):
            target = 'https://' + target
        scan_api(target)
        print("\n[V] Escaneo de APIs finalizado.")
        return
 
    if not os.path.exists(TARGETS_FILE):
        print(f"[-] No existe {TARGETS_FILE}")
        print(f"    Uso: python3 {sys.argv[0]} https://objetivo.com")
        return
 
    with open(TARGETS_FILE, 'r', encoding='utf-8', errors='replace') as fh:
        urls = [line.strip() for line in fh if line.strip()]
 
    for target in urls:
        if not target.startswith('http'):
            target = 'https://' + target
        scan_api(target)
 
    print("\n[V] Escaneo de APIs finalizado.")
 
 
if __name__ == "__main__":
    main()