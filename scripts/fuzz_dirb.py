import subprocess
import json
import os
import psycopg2
import re

# CONFIGURACIÓN
OUTPUT_DIR = "/home/anubis/Escaneos_Automatizados/script/dirb"
DATABASE_URL = "postgresql://admin:secretpassword@localhost:5432/ciber_db"
WORDLIST = "/usr/share/wordlists/dirb/common.txt"

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

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

        print(f"[+] DIRB finalizado para {name}. Hallazgos: {len(found_paths)}")
        update_db_status(url, "Fuzzing DIRB OK")

    except Exception as e:
        print(f"[!] Error en DIRB para {name}: {str(e)}")

def main():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("SELECT name, url FROM targets")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        for name, url in rows:
            run_dirb(name, url)
    except Exception as e:
        print(f"Error DB: {e}")

if __name__ == "__main__":
    main()
