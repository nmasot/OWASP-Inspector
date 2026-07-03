import httpx
import re
import time
from bs4 import BeautifulSoup

SQL_ERROR_PATTERNS = [
    r"mysql_fetch", r"ORA-\d+", r"SQLSTATE", r"sqlite3\.", r"pg_query",
    r"syntax error.*sql", r"unclosed quotation mark", r"microsoft ole db",
    r"odbc.*driver", r"warning.*mysql", r"division by zero in query",
    r"supplied argument is not a valid mysql"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
]

SQLI_PAYLOADS = [
    ("' OR '1'='1", "error"),
    ("1 AND 1=1--", "delay"),
    ("1' AND SLEEP(3)--", "delay"),
]

async def scan(target: str, mode: str) -> list:
    findings = []

    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
        try:
            r = await client.get(target)
            csp = r.headers.get("content-security-policy", "")
            body = r.text

            csp_status = "PASS"
            csp_detail = f"CSP presente: {csp[:120]}..."
            if not csp:
                csp_status = "VULNERABLE"
                csp_detail = "El header Content-Security-Policy está AUSENTE."
            elif "unsafe-inline" in csp or "unsafe-eval" in csp:
                csp_status = "VULNERABLE"
                csp_detail = f"CSP contiene directivas inseguras: {csp[:120]}"

            findings.append({
                "id": "A03",
                "name": "Inyección — Content Security Policy",
                "severity": "HIGH",
                "status": csp_status,
                "details": csp_detail,
                "remediation": "Implementa una CSP estricta sin las directivas 'unsafe-inline' ni 'unsafe-eval'. Usa nonces o hashes en su lugar."
            })

            sql_errors = [p for p in SQL_ERROR_PATTERNS if re.search(p, body, re.IGNORECASE)]
            findings.append({
                "id": "A03",
                "name": "Inyección — Exposición de Errores SQL",
                "severity": "CRITICAL" if sql_errors else "INFO",
                "status": "VULNERABLE" if sql_errors else "PASS",
                "details": f"Patrones de error SQL encontrados: {sql_errors}" if sql_errors else "No se detectaron mensajes de error SQL en la página principal.",
                "remediation": "Suprime los errores de base de datos en producción. Usa páginas de error genéricas sin información técnica."
            })

        except Exception as e:
            findings.append({
                "id": "A03",
                "name": "Inyección — Error de verificación base",
                "severity": "INFO",
                "status": "INFO",
                "details": str(e),
                "remediation": "Asegúrate de que el objetivo sea accesible."
            })

        if mode == "active":
            xss_found = False
            for payload in XSS_PAYLOADS:
                try:
                    r = await client.get(target, params={"q": payload, "search": payload, "id": payload})
                    if payload in r.text:
                        xss_found = True
                        findings.append({
                            "id": "A03-ACTIVO",
                            "name": "Inyección — XSS Reflejado",
                            "severity": "CRITICAL",
                            "status": "VULNERABLE",
                            "details": f"Payload reflejado sin escapar: {payload[:80]}",
                            "remediation": "Sanitiza y escapa toda entrada del usuario antes de renderizarla en HTML. Implementa una CSP estricta."
                        })
                        break
                except Exception:
                    pass

            if not xss_found:
                findings.append({
                    "id": "A03-ACTIVO",
                    "name": "Inyección — XSS Reflejado",
                    "severity": "CRITICAL",
                    "status": "PASS",
                    "details": "No se detectó reflejo de payloads XSS en los parámetros probados.",
                    "remediation": "Continúa con la sanitización de entradas. Usa un WAF como defensa adicional."
                })

            sqli_found = False
            for payload, ptype in SQLI_PAYLOADS:
                try:
                    start = time.time()
                    r = await client.get(target, params={"id": payload, "q": payload})
                    elapsed = time.time() - start
                    body = r.text.lower()
                    sql_err = any(re.search(p, body, re.IGNORECASE) for p in SQL_ERROR_PATTERNS)

                    if sql_err or (ptype == "delay" and elapsed > 2.5):
                        sqli_found = True
                        findings.append({
                            "id": "A03-ACTIVO",
                            "name": "Inyección — SQL Injection",
                            "severity": "CRITICAL",
                            "status": "VULNERABLE",
                            "details": f"Payload '{payload}' generó {'error de BD' if sql_err else f'demora sospechosa ({elapsed:.1f}s)'}",
                            "remediation": "Usa consultas parametrizadas o sentencias preparadas. Nunca concatenes entradas del usuario directamente en SQL."
                        })
                        break
                except Exception:
                    pass

            if not sqli_found:
                findings.append({
                    "id": "A03-ACTIVO",
                    "name": "Inyección — SQL Injection",
                    "severity": "CRITICAL",
                    "status": "PASS",
                    "details": "No se detectaron indicadores de SQLi en los parámetros probados.",
                    "remediation": "Continúa usando consultas parametrizadas y validación estricta de entradas."
                })

    return findings
