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

def _wordlist_size():
    try:
        with open(WORDLIST) as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0

# Cuántas palabras probadas se reportan antes de emitir un mensaje de progreso.
# dirb sin -S imprime una línea "--> Testing: <url>" por palabra, así que sin
# este límite se publicaría un mensaje por cada una de las ~4600+ palabras.
PROGRESS_EVERY = 25

def run_dirb(name, url):
    clean_name = name.lower().replace(" ", "_")
    final_output_file = os.path.join(OUTPUT_DIR, f"{clean_name}.json")

    print(f"[*] DIRB: Escaneando {url}...")
    total_words = _wordlist_size()

    try:
        # Sin -S (silent): dirb reporta cada palabra probada como línea de
        # progreso. Antes se usaba -S + subprocess.run(capture_output=True),
        # que se queda bloqueado sin imprimir nada hasta que el proceso entero
        # termina — un escaneo real contra celsiainternet.com tardó 116 min
        # sin ninguna señal de avance, indistinguible de un proceso colgado.
        proc = subprocess.Popen(
            ['dirb', url, WORDLIST],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )

        found_paths = []
        tested = 0
        buf = ''

        # dirb separa sus líneas de progreso con '\r' (barra de progreso en
        # terminal), no '\n' — un readline() normal nunca las vería y se
        # quedaría esperando indefinidamente a la primera línea real con '\n'.
        while True:
            chunk = proc.stdout.read(256)
            if not chunk:
                break
            buf += chunk
            while True:
                m = re.search(r'[\r\n]', buf)
                if not m:
                    break
                line, buf = buf[:m.start()].strip(), buf[m.end():]
                if not line:
                    continue

                if line.startswith('--> Testing:'):
                    tested += 1
                    if tested % PROGRESS_EVERY == 0:
                        pct = f" ({tested * 100 // total_words}%)" if total_words else ""
                        print(f"[.] DIRB: {tested} rutas probadas{pct}...", flush=True)
                        update_db_status(url, f"Fuzzing DIRB: {tested} probadas{pct}")
                elif "(CODE:" in line:
                    print(f"[+] {line}", flush=True)
                    match = re.search(r'\+ (.*) \(CODE:(\d+)', line)
                    if match:
                        full_url = match.group(1)
                        code = match.group(2)
                        # Solo guardamos el path relativo para el Dashboard
                        relative_path = full_url.replace(url, "")
                        found_paths.append({"path": relative_path, "status": code})
                elif line.startswith('==> DIRECTORY:'):
                    print(f"[+] {line}", flush=True)

        proc.wait()

        with open(final_output_file, 'w') as f:
            json.dump({"tool": "dirb", "results": found_paths}, f, indent=4)

        findings = [{
            "severity": _severity_for_status(p["status"]),
            "title": f"Ruta expuesta: {p['path']} (HTTP {p['status']})",
            "description": f"DIRB encontró la ruta '{p['path']}' con código de respuesta {p['status']}.",
            "extra": {"path": p["path"], "status": p["status"], "tool": "dirb"},
        } for p in found_paths]
        save_findings(url, 'fuzz_dirb', findings)

        print(f"[+] DIRB finalizado para {name}. Rutas probadas: {tested}. Hallazgos: {len(found_paths)}")
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
