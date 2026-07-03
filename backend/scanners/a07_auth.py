import httpx
from bs4 import BeautifulSoup

async def scan(target: str, mode: str) -> list:
    findings = []

    async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
        try:
            r = await client.get(target + "/login")
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                forms = soup.find_all("form")
                autocomplete_off = any(
                    f.get("autocomplete") == "off" or
                    any(i.get("autocomplete") == "off" for i in f.find_all("input"))
                    for f in forms
                )
                findings.append({
                    "id": "A07",
                    "name": "Fallas de Autenticación — Autocompletado en Login",
                    "severity": "LOW",
                    "status": "PASS" if autocomplete_off else "VULNERABLE",
                    "details": "El formulario de login tiene autocomplete=off." if autocomplete_off else "El formulario de login no tiene autocomplete=off — las credenciales pueden ser guardadas por el navegador.",
                    "remediation": "Agrega autocomplete='off' al formulario de login y a los campos de contraseña."
                })
        except Exception:
            findings.append({
                "id": "A07",
                "name": "Fallas de Autenticación — Autocompletado en Login",
                "severity": "LOW",
                "status": "INFO",
                "details": "No se encontró la ruta /login.",
                "remediation": "Asegúrate de que los formularios de login usen autocomplete='off' en los campos de contraseña."
            })

        try:
            r = await client.get(target)
            cookies_raw = r.headers.get("set-cookie", "")
            if cookies_raw:
                issues = []
                if "httponly" not in cookies_raw.lower():
                    issues.append("HttpOnly ausente")
                if "secure" not in cookies_raw.lower():
                    issues.append("Secure ausente")
                if "samesite" not in cookies_raw.lower():
                    issues.append("SameSite ausente")
                findings.append({
                    "id": "A07",
                    "name": "Fallas de Autenticación — Flags de Seguridad en Cookies",
                    "severity": "HIGH" if issues else "INFO",
                    "status": "VULNERABLE" if issues else "PASS",
                    "details": f"Flags de cookie faltantes: {', '.join(issues)}" if issues else "Todos los flags de seguridad en cookies están presentes.",
                    "remediation": "Configura las cookies de sesión con los atributos: HttpOnly; Secure; SameSite=Strict."
                })
            else:
                findings.append({
                    "id": "A07",
                    "name": "Fallas de Autenticación — Flags de Seguridad en Cookies",
                    "severity": "INFO",
                    "status": "INFO",
                    "details": "No se encontró el header Set-Cookie en la respuesta.",
                    "remediation": "Asegúrate de que las cookies de sesión usen HttpOnly, Secure y SameSite."
                })

            rate_headers = ["x-ratelimit-limit", "x-rate-limit-limit", "retry-after", "ratelimit-limit"]
            has_rate = any(h in r.headers for h in rate_headers)
            findings.append({
                "id": "A07",
                "name": "Fallas de Autenticación — Limitación de Intentos",
                "severity": "MEDIUM",
                "status": "PASS" if has_rate else "VULNERABLE",
                "details": "Headers de rate-limiting detectados." if has_rate else "No se detectaron headers de rate-limiting — un ataque de fuerza bruta podría ser posible.",
                "remediation": "Implementa limitación de intentos de login y bloqueo de cuenta. Agrega CAPTCHA después de N intentos fallidos."
            })
        except Exception as e:
            findings.append({
                "id": "A07",
                "name": "Fallas de Autenticación",
                "severity": "INFO",
                "status": "INFO",
                "details": str(e),
                "remediation": "Asegúrate de que el objetivo sea accesible."
            })

    return findings
