import httpx
from bs4 import BeautifulSoup

CDN_DOMAINS = ["cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "ajax.googleapis.com"]

async def scan(target: str, mode: str) -> list:
    findings = []

    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
        try:
            r = await client.get(target)
            soup = BeautifulSoup(r.text, "html.parser")

            missing_sri = []
            for script in soup.find_all("script", src=True):
                src = script.get("src", "")
                if any(cdn in src for cdn in CDN_DOMAINS):
                    if not script.get("integrity"):
                        missing_sri.append(src[:80])

            findings.append({
                "id": "A08",
                "name": "Integridad de Datos — Integridad de Subrecursos (SRI) Faltante",
                "severity": "MEDIUM" if missing_sri else "INFO",
                "status": "VULNERABLE" if missing_sri else "PASS",
                "details": f"Scripts de CDN sin SRI: {missing_sri}" if missing_sri else "Todos los scripts de CDN tienen el atributo de integridad SRI.",
                "remediation": "Agrega integrity='sha384-...' crossorigin='anonymous' a todos los scripts alojados en CDNs externos."
            })

            cors = r.headers.get("access-control-allow-origin", "")
            findings.append({
                "id": "A08",
                "name": "Integridad de Datos — CORS con Comodín",
                "severity": "HIGH" if cors == "*" else "INFO",
                "status": "VULNERABLE" if cors == "*" else "PASS",
                "details": f"Access-Control-Allow-Origin: {cors or 'no configurado'}",
                "remediation": "Restringe CORS a orígenes específicos y confiables en lugar de usar el comodín '*'."
            })

            csp = r.headers.get("content-security-policy", "")
            unsafe = []
            if "unsafe-inline" in csp:
                unsafe.append("'unsafe-inline'")
            if "unsafe-eval" in csp:
                unsafe.append("'unsafe-eval'")
            findings.append({
                "id": "A08",
                "name": "Integridad de Datos — Directivas CSP Inseguras",
                "severity": "HIGH" if unsafe else "INFO",
                "status": "VULNERABLE" if unsafe else ("PASS" if csp else "VULNERABLE"),
                "details": f"Directivas CSP inseguras: {', '.join(unsafe)}" if unsafe else (f"CSP configurada: {csp[:100]}" if csp else "Header CSP ausente."),
                "remediation": "Elimina 'unsafe-inline' y 'unsafe-eval' de la CSP. Usa nonces o hashes para scripts inline autorizados."
            })

        except Exception as e:
            findings.append({
                "id": "A08",
                "name": "Integridad de Datos",
                "severity": "INFO",
                "status": "INFO",
                "details": str(e),
                "remediation": "Asegúrate de que el objetivo sea accesible."
            })

    return findings
