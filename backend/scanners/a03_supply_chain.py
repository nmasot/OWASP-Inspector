import httpx
import re
from bs4 import BeautifulSoup

KNOWN_VULNERABLE = {
    "apache": {"eol_below": "2.4.50", "cve": "CVE-2021-41773"},
    "php": {"eol_below": "8.0.0", "cve": "Múltiples CVEs EOL"},
    "nginx": {"eol_below": "1.20.0", "cve": "Múltiples CVEs anteriores"},
    "openssl": {"eol_below": "1.1.1", "cve": "Múltiples CVEs"},
}

JQUERY_EOL = ["1.", "2.", "3.0.", "3.1.", "3.2.", "3.3.", "3.4.", "3.5."]

VERSION_RE = re.compile(
    r"(apache|nginx|php|openssl|express|tomcat)[/\s]([\d]+\.[\d]+\.?[\d]*)",
    re.IGNORECASE
)

def version_compare(v1: str, v2: str) -> int:
    def parts(v): return [int(x) for x in v.split(".")]
    try:
        p1, p2 = parts(v1), parts(v2)
        for a, b in zip(p1, p2):
            if a < b: return -1
            if a > b: return 1
        return 0
    except Exception:
        return 0

async def scan(target: str, mode: str) -> list:
    findings = []

    async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
        try:
            r = await client.get(target)
            server = r.headers.get("server", "")
            x_powered = r.headers.get("x-powered-by", "")
            combined = server + " " + x_powered

            vuln_tech = []
            for match in VERSION_RE.finditer(combined):
                tech = match.group(1).lower()
                version = match.group(2)
                if tech in KNOWN_VULNERABLE:
                    eol = KNOWN_VULNERABLE[tech]["eol_below"]
                    cve = KNOWN_VULNERABLE[tech]["cve"]
                    if version_compare(version, eol) < 0:
                        vuln_tech.append(f"{tech}/{version} (vulnerable, actualiza a >={eol}, ref: {cve})")

            findings.append({
                "id": "A06",
                "name": "Componentes Vulnerables — Versión del Servidor",
                "severity": "HIGH" if vuln_tech else "INFO",
                "status": "VULNERABLE" if vuln_tech else "PASS",
                "details": "; ".join(vuln_tech) if vuln_tech else f"Server: '{server}' — no se detectaron versiones vulnerables conocidas.",
                "remediation": "Mantén el software del servidor actualizado. Suscríbete a avisos de seguridad (CVE, NVD) para las tecnologías que usas."
            })

            soup = BeautifulSoup(r.text, "html.parser")
            jquery_issues = []
            for script in soup.find_all("script", src=True):
                src = script["src"]
                m = re.search(r"jquery[.-]([\d]+\.[\d]+\.?[\d]*)(\\.min)?\.js", src, re.IGNORECASE)
                if m:
                    jv = m.group(1)
                    if any(jv.startswith(eol) for eol in JQUERY_EOL):
                        jquery_issues.append(f"jQuery {jv} (EOL)")

            findings.append({
                "id": "A06",
                "name": "Componentes Vulnerables — jQuery Obsoleto",
                "severity": "MEDIUM" if jquery_issues else "INFO",
                "status": "VULNERABLE" if jquery_issues else "PASS",
                "details": f"Versiones jQuery EOL detectadas: {', '.join(jquery_issues)}" if jquery_issues else "No se detectaron versiones obsoletas de jQuery.",
                "remediation": "Actualiza jQuery a la última versión estable (3.7+). Evalúa migrar a JS moderno sin dependencia de jQuery."
            })

        except Exception as e:
            findings.append({
                "id": "A06",
                "name": "Componentes Vulnerables",
                "severity": "INFO",
                "status": "INFO",
                "details": f"No se pudo analizar: {e}",
                "remediation": "Asegúrate de que el objetivo sea accesible."
            })

    return findings
