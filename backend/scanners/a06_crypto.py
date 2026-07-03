import ssl
import socket
import httpx
from urllib.parse import urlparse

def check_tls_version(hostname: str, port: int = 443) -> dict:
    results = {}
    for proto, ver in [
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            with socket.create_connection((hostname, port), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    results[proto] = True
        except Exception:
            results[proto] = False
    return results

async def scan(target: str, mode: str) -> list:
    findings = []
    parsed = urlparse(target)
    hostname = parsed.hostname or parsed.path

    async with httpx.AsyncClient(timeout=8, follow_redirects=False, verify=False) as client:
        try:
            http_url = f"http://{hostname}"
            r = await client.get(http_url)
            location = r.headers.get("location", "")
            if r.status_code in (301, 302) and location.startswith("https://"):
                hsts = "PASS"
                hsts_detail = "HTTP redirige correctamente a HTTPS."
            else:
                hsts = "VULNERABLE"
                hsts_detail = "HTTP no redirige a HTTPS. Los datos se transmiten en texto plano."
        except Exception as e:
            hsts = "INFO"
            hsts_detail = f"No se pudo verificar la redirección HTTP→HTTPS: {e}"

        try:
            https_url = f"https://{hostname}"
            r2 = await client.get(https_url)
            hsts_header = r2.headers.get("strict-transport-security", "")
            xct = r2.headers.get("x-content-type-options", "")
        except Exception:
            hsts_header = ""
            xct = ""

    findings.append({
        "id": "A02",
        "name": "Fallos Criptográficos — Forzado de HTTPS",
        "severity": "HIGH",
        "status": hsts,
        "details": hsts_detail,
        "remediation": "Configura la redirección HTTP→HTTPS (código 301). Habilita HSTS con la directiva includeSubDomains."
    })

    findings.append({
        "id": "A02",
        "name": "Fallos Criptográficos — Header HSTS",
        "severity": "MEDIUM",
        "status": "PASS" if hsts_header else "VULNERABLE",
        "details": f"Strict-Transport-Security: {hsts_header or 'AUSENTE'}",
        "remediation": "Agrega el header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    })

    findings.append({
        "id": "A02",
        "name": "Fallos Criptográficos — X-Content-Type-Options",
        "severity": "LOW",
        "status": "PASS" if xct == "nosniff" else "VULNERABLE",
        "details": f"X-Content-Type-Options: {xct or 'AUSENTE'}",
        "remediation": "Agrega el header: X-Content-Type-Options: nosniff para evitar el MIME sniffing."
    })

    try:
        tls_results = check_tls_version(hostname)
        weak = [p for p, v in tls_results.items() if v]
        findings.append({
            "id": "A02",
            "name": "Fallos Criptográficos — Versiones TLS Débiles",
            "severity": "HIGH",
            "status": "VULNERABLE" if weak else "PASS",
            "details": f"Protocolos TLS débiles habilitados: {', '.join(weak)}" if weak else "TLS 1.0 y 1.1 están deshabilitados. Correcto.",
            "remediation": "Deshabilita TLS 1.0 y TLS 1.1 en el servidor. Usa únicamente TLS 1.2 o superior."
        })
    except Exception as e:
        findings.append({
            "id": "A02",
            "name": "Fallos Criptográficos — Versión TLS",
            "severity": "INFO",
            "status": "INFO",
            "details": f"Verificación TLS omitida (no es HTTPS o no es alcanzable): {e}",
            "remediation": "Asegúrate de que el objetivo use HTTPS con TLS 1.2 o superior."
        })

    return findings
