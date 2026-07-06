import subprocess
import json
import os
import sys
import psycopg2
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db_findings import save_findings

# CONFIGURACIÓN
OUTPUT_DIR = "/home/anubis/AnubisProject/reports/fuzz_dirb"
DATABASE_URL = "postgresql://admin:Malware2030$@localhost:5432/ciber_db"
WORDLIST = "/usr/share/wordlists/dirb/common.txt"

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

def _severity_for_status(code):
    code = str(code)
    if code in ("200", "204"):
        return "medium"
    if code in ("301", "302", "307"):
        return "low"
    return "info"

def update_db_status(url, message):
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("UPDATE targets SET status = %s WHERE url = %s", (message, url))
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error DB status: {e}")

def run_dirb(name, url):
    clean_name = name.lower().replace(" ", "_")
    final_output_file = os.path.join(OUTPUT_DIR, f"{clean_name}.json")

    print(f"[*] DIRB: Escaneando {url}...")

    try:
        # Ejecutamos DIRB -S (Silent)
        result = subprocess.run(['dirb', url, WORDLIST, '-S'], capture_output=True, text=True)

        found_paths = []
        # Buscamos líneas que contengan CODE:200 o CODE:301/302
        # Ejemplo: ==> DIRECTORY: http://url/admin/
        # Ejemplo: + http://url/index.php (CODE:200|SIZE:123)
        lines = result.stdout.splitlines()
        for line in lines:
            if "(CODE:" in line:
                match = re.search(r'\+ (.*) \(CODE:(\d+)', line)
                if match:
                    full_url = match.group(1)
                    code = match.group(2)
                    # Solo guardamos el path relativo para el Dashboard
                    relative_path = full_url.replace(url, "")
                    found_paths.append({"path": relative_path, "status": code})

        with open(final_output_file, 'w') as f:
            json.dump({"tool": "dirb", "results": found_paths}, f, indent=4)

        findings = [{
            "severity": _severity_for_status(p["status"]),
            "title": f"Ruta expuesta: {p['path']} (HTTP {p['status']})",
            "description": f"DIRB encontró la ruta '{p['path']}' con código de respuesta {p['status']}.",
            "extra": {"path": p["path"], "status": p["status"], "tool": "dirb"},
        } for p in found_paths]
        save_findings(url, 'fuzz_dirb', findings)

        print(f"[+] DIRB finalizado para {name}. Hallazgos: {len(found_paths)}")
        update_db_status(url, "Fuzzing DIRB OK")

    except Exception as e:
        print(f"[!] Error en DIRB para {name}: {str(e)}")

def get_name_for_url(url):
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("SELECT name FROM targets WHERE url = %s", (url,))
        result = cur.fetchone()
        cur.close()
        conn.close()
        if result:
            return result[0]
    except Exception as e:
        print(f"Error DB: {e}")
    return url.replace('https://', '').replace('http://', '').split('/')[0].split('.')[0]

def main():
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 fuzz_dirb.py <url>")
        return

    target_url = sys.argv[1]
    if not target_url.startswith('http'):
        target_url = 'https://' + target_url

    name = get_name_for_url(target_url)
    run_dirb(name, target_url)

if __name__ == "__main__":
    main()
