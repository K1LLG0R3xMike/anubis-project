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
REPORTS_DIR = "/home/anubis/AnubisProject/reports/whatweb"
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
            
            # Reemplazos usando secuencias de escape de Python para evitar caracteres especiales en el codigo
            # \u00e1 = a con acento, \u00e9 = e con acento, etc.
            name = name.replace('\u00e1', 'a').replace('\u00e9', 'e')
            name = name.replace('\u00ed', 'i').replace('\u00f3', 'o')
            name = name.replace('\u00fa', 'u').replace('\u00f1', 'n')
            
            # Solo permitir minusculas, numeros y guiones bajos
            name = re.sub(r'\s+', '_', name)
            name = re.sub(r'[^a-z0-9_]', '', name)
            return name
    except:
        pass
    
    return url.replace('https://', '').replace('http://', '').split('/')[0].split('.')[0].lower()

def run_whatweb(url):
    clean_name = get_target_name_from_db(url)
    temp_raw_file = os.path.join(REPORTS_DIR, f"raw_what_{clean_name}.json")
    final_output_file = os.path.join(REPORTS_DIR, f"{clean_name}.json")
    
    if os.path.exists(temp_raw_file): os.remove(temp_raw_file)

    print(f"[*] Analizando: {url} -> {clean_name}.json")
    
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    try:
        subprocess.run([
            'whatweb', '--color=never', '--log-json', temp_raw_file,
            '--user-agent', user_agent, '--aggression', '1', url
        ], capture_output=True, text=True, errors='replace')

        if os.path.exists(temp_raw_file):
            with open(temp_raw_file, 'r', encoding='utf-8', errors='replace') as f:
                try:
                    raw_data = json.load(f)
                    techs = list(raw_data[0].get("plugins", {}).keys()) if raw_data else []
                    
                    with open(final_output_file, 'w', encoding='utf-8') as f_out:
                        json.dump({"target": url, "technologies": techs}, f_out, indent=4)

                    save_findings(url, 'whatweb', [
                        {'severity': 'info', 'title': tech,
                         'description': f'Tecnología detectada: {tech}', 'extra': {}}
                        for tech in techs
                    ])
                    update_db_status(url, "Tecnologias Identificadas")
                except:
                    pass
            
            if os.path.exists(temp_raw_file): os.remove(temp_raw_file)
    except Exception as e:
        print(f"[-] Error: {str(e)}")

def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 whatweb.py <url>")
        return

    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR, mode=0o777, exist_ok=True)

    target = sys.argv[1]
    target_url = target if target.startswith('http') else 'https://' + target
    run_whatweb(target_url)

if __name__ == "__main__":
    main()