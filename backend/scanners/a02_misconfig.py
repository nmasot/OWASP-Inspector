import httpx

DEFAULT_ERROR_FINGERPRINTS = [
    "apache tomcat", "nginx", "iis", "php warning", "laravel",
    "ruby on rails", "django", "stack trace", "traceback"
]

async def scan(target: str, mode: str) -> list:
    findings = []

    async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
        try:
            r = await client.get(target)
            headers = r.headers

            xfo = headers.get("x-frame-options", "")
            findings.append({
                "id": "A05",
                "name": "Mala Configuración de Seguridad — X-Frame-Options",
                "severity": "MEDIUM",
                "status": "PASS" if xfo else "VULNERABLE",
                "details": f"X-Frame-Options: {xfo or 'AUSENTE'}",
                "remediation": "Agrega el header X-Frame-Options: DENY o SAMEORIGIN para prevenir ataques de clickjacking."
            })

            xpb = headers.get("x-powered-by", "")
            findings.append({
                "id": "A05",
                "name": "Mala Configuración — Divulgación X-Powered-By",
                "severity": "LOW",
                "status": "VULNERABLE" if xpb else "PASS",
                "details": f"X-Powered-By: {xpb or 'no presente (correcto)'}",
                "remediation": "Elimina el header X-Powered-By para evitar la divulgación de la tecnología utilizada."
            })

            pp = headers.get("permissions-policy", "")
            findings.append({
                "id": "A05",
                "name": "Mala Configuración — Permissions-Policy",
                "severity": "LOW",
                "status": "PASS" if pp else "VULNERABLE",
                "details": f"Permissions-Policy: {pp or 'AUSENTE'}",
                "remediation": "Agrega el header Permissions-Policy para controlar el acceso a funciones del navegador (cámara, geolocalización, etc.)."
            })

            error_page = ""
            try:
                re = await client.get(target + "/this-path-should-not-exist-12345")
                body_lower = re.text.lower()
                for fp in DEFAULT_ERROR_FINGERPRINTS:
                    if fp in body_lower:
                        error_page = fp
                        break
            except Exception:
                pass

            findings.append({
                "id": "A05",
                "name": "Mala Configuración — Fingerprinting por Páginas de Error",
                "severity": "LOW",
                "status": "VULNERABLE" if error_page else "PASS",
                "details": f"La página de error revela el framework: '{error_page}'" if error_page else "Las páginas de error no revelan la tecnología utilizada.",
                "remediation": "Usa páginas de error personalizadas y genéricas que no divulguen información técnica del servidor."
            })

        except Exception as e:
            findings.append({
                "id": "A05",
                "name": "Mala Configuración de Seguridad",
                "severity": "INFO",
                "status": "INFO",
                "details": f"No se pudo alcanzar el objetivo: {e}",
                "remediation": "Asegúrate de que el objetivo sea accesible."
            })

        if mode == "active":
            try:
                r = await client.request("TRACE", target)
                trace_ok = r.status_code == 200 and "TRACE" in r.text.upper()
                findings.append({
                    "id": "A05-ACTIVO",
                    "name": "Mala Configuración — Método HTTP TRACE",
                    "severity": "MEDIUM",
                    "status": "VULNERABLE" if trace_ok else "PASS",
                    "details": "El método TRACE está habilitado (puede usarse en ataques XST)." if trace_ok else "El método TRACE está deshabilitado.",
                    "remediation": "Deshabilita los métodos HTTP peligrosos como TRACE y OPTIONS en la configuración del servidor."
                })
            except Exception:
                pass

    return findings
