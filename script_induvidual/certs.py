# -*- coding: utf-8 -*-
import subprocess
import json
import os
import sys
import psycopg2
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db_findings import save_findings

SSL_SEV = {
    'SSLv2':   'critical',
    'SSLv3':   'high',
    'TLS 1.0': 'medium',
    'TLS 1.1': 'low',
}

# --- CONFIGURACION ---
REPORTS_DIR = "/home/anubis/AnubisProject/reports/certs"
TARGETS_FILE = "/home/anubis/AnubisProject/reports/sitios.txt"
DATABASE_URL = "postgresql://admin:Malware2030$@localhost:5432/ciber_db"

def update_db_status(url, message):
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("UPDATE targets SET status = %s WHERE url = %s", (message, url))
        conn.commit()
        cur.close()
        conn.close()
        print(f"[#] DB actualizada: {url} -> {message}")
    except Exception as e:
        print(f"[!] Error DB: {e}")

def get_target_name_from_db(url):
    """Consulta el nombre asignado al objetivo en la base de datos y lo formatea como el Front"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        # Aseguramos que la URL tenga el protocolo para la consulta
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
    
    # Fallback: si falla la DB, usar el dominio
    name = url.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0].split(':')[0]
    return name.split('.')[0].lower()

def run_testssl(url):
    # CAMBIO CLAVE: Ahora obtenemos el nombre que coincide con el Dashboard
    clean_name = get_target_name_from_db(url)
    domain = url.replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
    
    temp_raw_file = os.path.join(REPORTS_DIR, f"raw_{clean_name}.json")
    final_output_file = os.path.join(REPORTS_DIR, f"{clean_name}.json")
    
    # Limpieza previa
    for f in [temp_raw_file, final_output_file]:
        if os.path.exists(f): os.remove(f)

    print(f"\n[*] Analizando SSL/TLS para: {domain} -> {clean_name}.json")
    
    try:
        subprocess.run([
            'testssl', 
            '--quiet', 
            '--warnings', 'off', 
            '--overwrite', 
            '--jsonfile-pretty', temp_raw_file, 
            domain
        ], capture_output=True, text=True)

        if os.path.exists(temp_raw_file):
            with open(temp_raw_file, 'r') as f:
                raw_data = json.load(f)
            
            interest_ids = {
                'SSLv2': 'SSLv2',
                'SSLv3': 'SSLv3',
                'TLS1': 'TLS 1.0',
                'TLS1_1': 'TLS 1.1',
                'TLS1_2': 'TLS 1.2',
                'TLS1_3': 'TLS 1.3'
            }
            
            filtered_protocols = {}

            if "scanResult" in raw_data and len(raw_data["scanResult"]) > 0:
                protocols_list = raw_data["scanResult"][0].get("protocols", [])
                for entry in protocols_list:
                    p_id = entry.get('id')
                    if p_id in interest_ids:
                        finding = entry.get('finding', '').lower()
                        status = "Soportado" if "offered" in finding and "not offered" not in finding else "No Soportado"
                        filtered_protocols[interest_ids[p_id]] = status

            with open(final_output_file, 'w') as f:
                json.dump({"protocols": filtered_protocols}, f, indent=4)

            cert_findings = [
                {'severity': SSL_SEV[p],
                 'title': f'Protocolo inseguro activo: {p}',
                 'description': f'{p} está habilitado. Se recomienda deshabilitar versiones obsoletas de SSL/TLS.',
                 'extra': {'protocol': p, 'status': s}}
                for p, s in filtered_protocols.items()
                if s == 'Soportado' and p in SSL_SEV
            ]
            save_findings(url, 'certs', cert_findings)

            if os.path.exists(temp_raw_file): os.remove(temp_raw_file)

            print(f"[+] Reporte SSL guardado: {clean_name}.json")
            update_db_status(url, "SSL Analizado")
        else:
            print(f"[!] testssl no genero resultados para {domain}")
            
    except Exception as e:
        print(f"[-] Error en {domain}: {str(e)}")

def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 certs.py <url>")
        return

    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR, mode=0o777, exist_ok=True)

    target = sys.argv[1]
    if not target.startswith('http'):
        target = 'https://' + target
    run_testssl(target)

if __name__ == "__main__":
    main()