import httpx

LOG_PATHS = [
    "/logs", "/error.log", "/access.log", "/debug.log", "/app.log",
    "/log.txt", "/logs/error.log", "/logs/access.log"
]

BACKUP_PATHS = [
    "/index.php.bak", "/index.bak", "/db.sql", "/database.sql",
    "/backup.zip", "/backup.tar.gz", "/config.old", "/wp-config.php.bak",
    "/.env.bak", "/app.js.bak"
]

async def scan(target: str, mode: str) -> list:
    findings = []

    async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
        exposed_logs = []
        for path in LOG_PATHS:
            try:
                r = await client.get(target + path)
                if r.status_code in (200, 206) and len(r.text) > 50:
                    exposed_logs.append(path)
            except Exception:
                pass

        findings.append({
            "id": "A09",
            "name": "Registro y Monitoreo — Archivos de Log Expuestos",
            "severity": "HIGH" if exposed_logs else "INFO",
            "status": "VULNERABLE" if exposed_logs else "PASS",
            "details": f"Archivos de log accesibles: {', '.join(exposed_logs)}" if exposed_logs else "No se detectaron archivos de log expuestos.",
            "remediation": "Mueve los archivos de log fuera del webroot o restringe su acceso mediante la configuración del servidor web."
        })

        exposed_backups = []
        for path in BACKUP_PATHS:
            try:
                r = await client.get(target + path)
                if r.status_code == 200 and len(r.content) > 100:
                    exposed_backups.append(path)
            except Exception:
                pass

        findings.append({
            "id": "A09",
            "name": "Registro y Monitoreo — Archivos de Backup Expuestos",
            "severity": "CRITICAL" if exposed_backups else "INFO",
            "status": "VULNERABLE" if exposed_backups else "PASS",
            "details": f"Archivos de backup accesibles: {', '.join(exposed_backups)}" if exposed_backups else "No se detectaron archivos de backup expuestos.",
            "remediation": "Elimina los archivos de backup del webroot. Agrega reglas de denegación para extensiones .bak, .sql y .old en el servidor."
        })

        try:
            r = await client.get(target + "/robots.txt")
            if r.status_code == 200:
                sensitive_disallows = [
                    line.strip() for line in r.text.splitlines()
                    if line.lower().startswith("disallow:") and
                    any(kw in line.lower() for kw in ["/admin", "/backup", "/private", "/config", "/db", "/sql"])
                ]
                findings.append({
                    "id": "A09",
                    "name": "Registro y Monitoreo — Divulgación en robots.txt",
                    "severity": "LOW" if sensitive_disallows else "INFO",
                    "status": "VULNERABLE" if sensitive_disallows else "PASS",
                    "details": f"Rutas sensibles en robots.txt: {sensitive_disallows}" if sensitive_disallows else "Se encontró robots.txt pero no revela rutas sensibles.",
                    "remediation": "No listes rutas sensibles en robots.txt — usa autenticación adecuada en lugar de confiar en la oscuridad."
                })
            else:
                findings.append({
                    "id": "A09",
                    "name": "Registro y Monitoreo — robots.txt",
                    "severity": "INFO",
                    "status": "INFO",
                    "details": "No se encontró robots.txt.",
                    "remediation": "Considera crear un robots.txt sin revelar directorios sensibles."
                })
        except Exception:
            pass

    return findings
