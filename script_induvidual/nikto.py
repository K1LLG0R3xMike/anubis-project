# -*- coding: utf-8 -*-
import subprocess
import json
import os
import psycopg2
import re
import sys

# Forzamos la terminal a usar UTF-8
sys.stdout.reconfigure(encoding='utf-8', errors='ignore')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db_findings import save_findings

# --- CONFIGURACION ---
REPORTS_DIR = "/home/anubis/AnubisProject/reports/nikto"
TARGETS_FILE = "/home/anubis/AnubisProject/reports/sitios.txt"
DATABASE_URL = "postgresql://admin:Malware2030$@localhost:5432/ciber_db"

def update_db(url, vuln_count):
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        # Mensaje sin acentos para evitar errores de codificacion
        status_text = f"Nikto: {vuln_count} hallazgos"
        cur.execute("UPDATE targets SET status = %s WHERE url = %s", (status_text, url))
        conn.commit()
        cur.close()
        conn.close()
        print(f"[#] DB actualizada: {url} -> {status_text}")
    except:
        pass

def get_target_name_from_db(url):
    """Consulta el nombre y limpia caracteres usando codigos de escape para evitar SyntaxError"""
    try:
        conn = psycopg2.connect(DATABASE_URL)
        conn.set_client_encoding('UTF8')
        cur = conn.cursor()
        
        db_url = url if url.startswith('http') else 'https://' + url
        cur.execute("SELECT name FROM targets WHERE url = %s", (db_url,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        
        if result:
            name = str(result[0]).lower().strip()
            # Reemplazos Unicode para evitar caracteres especiales en el codigo .py
            name = name.replace('\u00e1', 'a').replace('\u00e9', 'e')
            name = name.replace('\u00ed', 'i').replace('\u00f3', 'o')
            name = name.replace('\u00fa', 'u').replace('\u00f1', 'n')
            
            # Solo permitir minusculas, numeros y guiones bajos
            name = re.sub(r'\s+', '_', name)
            name = re.sub(r'[^a-z0-9_]', '', name)
            return name
    except:
        pass
    
    return url.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0].split('.')[0].lower()

def run_nikto(url):
    clean_name = get_target_name_from_db(url)
    print(f"\n[*] Analizando Nikto: {url} -> {clean_name}.json")
    
    raw_output = os.path.join(REPORTS_DIR, f"raw_{clean_name}.json")
    final_output = os.path.join(REPORTS_DIR, f"{clean_name}.json")
    
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    evasion = "158"

    try:
        if os.path.exists(raw_output): os.remove(raw_output)
        if os.path.exists(final_output): os.remove(final_output)

        # Ejecutamos Nikto
        subprocess.run([
            'nikto',
            '-h', url,
            '-Format', 'json',
            '-o', raw_output,
            '-Tuning', '123b',
            '-evasion', evasion,
            '-useragent', user_agent,
            '-maxtime', '15m',
            '-nointeractive',
            '-Display', 'V',
        ], check=False)

        # Nikto a veces guarda como archivo.json o archivo.json.json
        actual_raw = raw_output if os.path.exists(raw_output) else f"{raw_output}.json"

        if os.path.exists(actual_raw):
            with open(actual_raw, 'r', encoding='utf-8', errors='ignore') as f:
                try:
                    data = json.load(f)
                    items = data if isinstance(data, list) else [data]
                    all_vulns = items[0].get('vulnerabilities', []) if items else []

                    clean_vulns = []
                    for v in all_vulns:
                        msg = v.get("msg", "")
                        
                        # LOGICA DE SEVERIDAD: Si el Dashboard espera 'high', 'medium', 'low'
                        # Intentamos detectar la severidad por palabras clave en el mensaje
                        severity = "low"
                        msg_lower = msg.lower()
                        if any(x in msg_lower for x in ["critical", "rce", "execution"]):
                            severity = "high"
                        elif any(x in msg_lower for x in ["vulnerable", "xss", "sql", "leak"]):
                            severity = "medium"

                        clean_vulns.append({
                            "msg": msg,
                            "url": v.get("url"),
                            "method": v.get("method"),
                            "severity": severity 
                        })

                    with open(final_output, 'w', encoding='utf-8') as f_out:
                        json.dump({"target": url, "vulnerabilities": clean_vulns}, f_out, indent=4)
                    
                    vuln_count = len(clean_vulns)
                    print(f"[+] Hallazgos: {vuln_count}")
                    update_db(url, vuln_count)
                    save_findings(url, 'nikto', [
                        {'severity': v['severity'],
                         'title': v['msg'],
                         'description': v.get('url', ''),
                         'extra': {'method': v.get('method', ''), 'url': v.get('url', '')}}
                        for v in clean_vulns
                    ])

                except Exception as je:
                    print(f"[!] Error procesando JSON: {je}")
            
            if os.path.exists(actual_raw): os.remove(actual_raw)
        else:
            print(f"[!] Nikto no genero resultados para {url}")
            update_db(url, 0)

    except Exception as e:
        print(f"[-] Error critico: {str(e)}")

def main():
    if len(sys.argv) < 2:
        print("Uso: python3 nikto.py <url>")
        return

    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR, mode=0o777, exist_ok=True)

    target = sys.argv[1]
    full_url = target if target.startswith('http') else 'https://' + target
    run_nikto(full_url)

if __name__ == "__main__":
    main()