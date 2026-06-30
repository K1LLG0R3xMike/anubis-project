# -*- coding: utf-8 -*-
import psycopg2
import json

DATABASE_URL = "postgresql://admin:Malware2030$@localhost:5432/ciber_db"

def save_findings(url, module, findings):
    """
    Reemplaza los hallazgos de url+module y guarda la nueva lista.
    findings: lista de dicts con claves:
        severity    (critical|high|medium|low|info)
        title       (str, obligatorio)
        description (str, opcional)
        extra       (dict, opcional)
    """
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()

        db_url = url if url.startswith('http') else 'https://' + url
        cur.execute("SELECT id FROM targets WHERE url = %s", (db_url,))
        row = cur.fetchone()
        if not row:
            print(f"[!] findings_db: target no encontrado para {url}")
            cur.close(); conn.close()
            return

        target_id = row[0]
        cur.execute(
            "DELETE FROM findings WHERE target_id = %s AND module = %s",
            (target_id, module)
        )

        for f in findings:
            cur.execute(
                """INSERT INTO findings (target_id, module, severity, title, description, extra)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (
                    target_id,
                    module,
                    f.get('severity'),
                    str(f['title'])[:500],
                    str(f.get('description', ''))[:1000],
                    json.dumps(f.get('extra') or {})
                )
            )

        cur.execute("UPDATE targets SET last_scan = NOW() WHERE id = %s", (target_id,))
        conn.commit()
        cur.close()
        conn.close()
        print(f"[#] findings_db: {len(findings)} hallazgos guardados [{module}] para {url}")
    except Exception as e:
        print(f"[!] findings_db error: {e}")
