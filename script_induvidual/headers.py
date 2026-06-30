# -*- coding: utf-8 -*-
import requests
import json
import os
import sys
import psycopg2
import urllib3
import re
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db_findings import save_findings

HEADER_SEV = {
    'Strict-Transport-Security': 'high',
    'Content-Security-Policy':   'medium',
    'X-Frame-Options':           'medium',
    'X-Content-Type-Options':    'low',
    'Referrer-Policy':           'low',
}

# Desactivar alertas de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- CONFIGURACION ---
REPORTS_DIR = "/home/anubis/AnubisProject/reports/headers"
TARGETS_FILE = "/home/anubis/AnubisProject/reports/sitios.txt"
DATABASE_URL = "postgresql://admin:Malware2030$@localhost:5432/ciber_db"

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy"
]

def get_target_name_from_db(url):
    """Consulta el nombre asignado al objetivo en la base de datos y lo formatea como el Front"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        # Aseguramos que la URL tenga el protocolo para la consulta exacta
        db_url = url if url.startswith('http') else 'https://' + url
        cur.execute("SELECT name FROM targets WHERE url = %s", (db_url,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        if result:
            # Replicamos l�gica del Dashboard: min�sculas, sin espacios extremos, espacios por _
            name = result[0].lower().strip()
            return re.sub(r'\s+', '_', name)
    except Exception as e:
        print(f"[!] Error consultando nombre: {e}")
    
    # Fallback: limpieza b�sica si no se encuentra en DB
    fallback = url.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0].split('.')[0]
    return fallback.lower()

def analyze_security_headers(url):
    # CAMBIO AQU�: Ahora obtenemos el nombre que coincide con el Dashboard
    clean_name = get_target_name_from_db(url)
    
    full_url = url if url.startswith('http') else 'https://' + url
    print(f"[*] Analizando cabeceras: {full_url} -> {clean_name}.json")
    
    final_path = os.path.join(REPORTS_DIR, f"{clean_name}.json")

    try:
        response = requests.get(full_url, timeout=10, verify=False)
        actual_headers = {k.lower(): v for k, v in response.headers.items()}
        
        results = {
            "site_url": full_url,
            "analysis_date": datetime.now().isoformat(),
            "security_headers": {}
        }
        
        score = 0
        for header in SECURITY_HEADERS:
            if header.lower() in actual_headers:
                results["security_headers"][header] = {
                    "status": "Presente",
                    "value": actual_headers[header.lower()]
                }
                score += 1
            else:
                results["security_headers"][header] = {
                    "status": "Faltante",
                    "value": None
                }

        with open(final_path, 'w') as f:
            json.dump(results, f, indent=4)

        header_findings = [
            {'severity': HEADER_SEV.get(h, 'low'),
             'title': f'Header faltante: {h}',
             'description': f'El header de seguridad {h} no está configurado.',
             'extra': {'header': h}}
            for h, d in results['security_headers'].items()
            if d['status'] == 'Faltante'
        ]
        save_findings(full_url, 'headers', header_findings)

        print(f"[+] Reporte guardado: {clean_name}.json ({score}/{len(SECURITY_HEADERS)})")

    except Exception as e:
        print(f"[-] Error analizando {full_url}: {e}")

def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 headers.py <url>")
        return

    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR, mode=0o777, exist_ok=True)

    target = sys.argv[1]
    analyze_security_headers(target)

if __name__ == "__main__":
    main()