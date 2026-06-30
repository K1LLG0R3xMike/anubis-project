import subprocess
import json
import os
import psycopg2

# CONFIGURACIÓN
OUTPUT_DIR = "/home/anubis/Escaneos_Automatizados/script/gobuster"
DATABASE_URL = "postgresql://admin:secretpassword@localhost:5432/ciber_db"
WORDLIST = "/usr/share/seclists/Discovery/Web-Content/common.txt"

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
        print(f"Error actualizando DB: {e}")

def run_gobuster(name, url):
    clean_name = name.lower().replace(" ", "_")
    final_output_file = os.path.join(OUTPUT_DIR, f"{clean_name}.json")
    
    # Limpiamos URL (quitar fragmentos #)
    target_url = url.split('#')[0]
    
    print(f"[*] Gobuster: Escaneando directorios en {target_url}...")
    
    try:
        # --- MEJORA: Definimos qué estados mostrar en lugar de qué estados borrar ---
        # Incluimos 200, 204 (éxitos), 301, 302, 307 (redirecciones) y 401, 403 (protegidos)
        # Añadimos un User-Agent real para evitar bloqueos por WAF
        result = subprocess.run([
            'gobuster', 'dir', 
            '-u', target_url, 
            '-w', WORDLIST,
            '-s', '200,204,301,302,307,401,403', 
            '-a', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            '-k', 
            '--no-error', 
            '-z'
        ], capture_output=True, text=True)

        found_paths = []
        
        # Procesamos la salida de Gobuster
        if result.stdout:
            for line in result.stdout.splitlines():
                if "Status:" in line:
                    # Ejemplo de línea: /admin (Status: 200) [Size: 123]
                    path = line.split('(')[0].strip()
                    status_part = line.split('Status:')[1].split(')')[0].strip()
                    found_paths.append({
                        "path": path, 
                        "status": status_part
                    })

        # Guardar en JSON con el formato que necesita el Dashboard
        with open(final_output_file, 'w') as f:
            json.dump({
                "target": name,
                "tool": "gobuster", 
                "results": found_paths
            }, f, indent=4)

        print(f"[+] Gobuster finalizado para {name}. Hallazgos: {len(found_paths)}")
        update_db_status(url, "Fuzzing Gobuster OK")

    except Exception as e:
        print(f"[!] Error en Gobuster para {name}: {str(e)}")

def main():
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        cur.execute("SELECT name, url FROM targets")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        
        for name, url in rows:
            run_gobuster(name, url)
            
    except Exception as e:
        print(f"Error conectando a la DB: {e}")

if __name__ == "__main__":
    main()
