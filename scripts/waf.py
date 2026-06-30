# -*- coding: utf-8 -*-
import subprocess
import json
import os
import sys
import psycopg2
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db_findings import save_findings

# --- CONFIGURACION ---
REPORTS_DIR = "/home/anubis/AnubisProject/reports/waf"
TARGETS_FILE = "/home/anubis/AnubisProject/reports/sitios.txt"
DATABASE_URL = "postgresql://admin:Malware2030$@localhost:5432/ciber_db"

def update_db(url, waf_name):
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        # Actualizamos el status para que el Dashboard lo muestre
        cur.execute("UPDATE targets SET status = %s WHERE url = %s", (f"WAF: {waf_name}", url))
        conn.commit()
        cur.close()
        conn.close()
        print(f"[#] DB actualizada: {url} -> {waf_name}")
    except Exception as e:
        print(f"[!] Error DB: {e}")

def get_target_name_from_db(url):
    """Consulta el nombre asignado al objetivo en la base de datos y lo formatea como el Front"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        # Buscamos el nombre usando la URL
        cur.execute("SELECT name FROM targets WHERE url = %s", (url,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        if result:
            # Replicamos l�gica del Dashboard: min�sculas, sin espacios extremos, espacios por _
            name = result[0].lower().strip()
            return re.sub(r'\s+', '_', name)
    except Exception as e:
        print(f"[!] Error consultando nombre: {e}")
    
    # Fallback: Si falla la DB o no encuentra el nombre, limpia la URL como recurso de emergencia
    fallback_name = url.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0].split('.')[0]
    return fallback_name.lower()

def check_waf(url):
    # Limpiamos la URL para el escaneo: quitamos rutas como /es/ para evitar falsos 'None'
    # wafw00f prefiere el dominio limpio
    base_url = re.match(r"https?://[0-9a-zA-Z.-]+(:[0-9]+)?", url)
    scan_url = base_url.group(0) if base_url else url
    
    print(f"\n[*] Analizando: {scan_url}")
    
    # CAMBIO AQU�: Ahora obtenemos el nombre que coincide con el Dashboard
    clean_name = get_target_name_from_db(url)
    final_output = os.path.join(REPORTS_DIR, f"{clean_name}.json")
    
    try:
        if os.path.exists(final_output):
            os.remove(final_output)
            
        # EJECUCION: -r (seguir redirecciones) y URL base
        subprocess.run(['wafw00f', scan_url, '-r', '-f', 'json', '-o', final_output], 
                       capture_output=True, text=True)
        
        if os.path.exists(final_output):
            with open(final_output, 'r') as f:
                try:
                    data = json.load(f)
                    waf_detected = data[0]['firewall'] if data else "None"
                except:
                    waf_detected = "Error JSON"
            
            print(f"[+] Detectado: {waf_detected} -> {clean_name}.json")
            update_db(url, waf_detected)
            save_findings(url, 'waf', [{
                'severity': 'info',
                'title': f'WAF: {waf_detected}',
                'description': f'Firewall de aplicación web detectado: {waf_detected}',
                'extra': {'firewall': waf_detected, 'detected': waf_detected not in ['None', 'Not Detected']}
            }])
        else:
            print(f"[!] Error: No se genero el JSON para {clean_name}")
            update_db(url, "Not Detected")
            save_findings(url, 'waf', [{
                'severity': 'info',
                'title': 'WAF: No Detectado',
                'description': 'No se detectó firewall de aplicación web.',
                'extra': {'firewall': None, 'detected': False}
            }])
    except Exception as e:
        print(f"[-] Error en el proceso: {e}")

def main():
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR, mode=0o777, exist_ok=True)
    
    if not os.path.exists(TARGETS_FILE):
        print(f"[-] No existe {TARGETS_FILE}")
        return

    with open(TARGETS_FILE, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    for target in urls:
        # Aseguramos que la URL tenga el protocolo para la consulta en DB
        if not target.startswith('http'):
            target = 'https://' + target
        check_waf(target)
    
    print("\n[V] Escaneo WAF finalizado.")

if __name__ == "__main__":
    main()