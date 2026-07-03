import httpx
import re

SENSITIVE_ENDPOINTS = [
    "/swagger.json", "/swagger-ui.html", "/openapi.json", "/api-docs",
    "/graphql", "/graphiql", "/v1/api-docs", "/v2/api-docs"
]

DEBUG_ENDPOINTS = [
    "/debug", "/trace", "/actuator", "/actuator/health", "/actuator/env",
    "/__debug__", "/server-status", "/server-info", "/_profiler"
]

VERSION_RE = re.compile(r"(apache|nginx|iis|php|tomcat|express|django|rails)[/\s]([\d.]+)", re.IGNORECASE)

async def scan(target: str, mode: str) -> list:
    findings = []

    async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
        exposed_docs = []
        for path in SENSITIVE_ENDPOINTS:
            try:
                r = await client.get(target + path)
                if r.status_code == 200 and len(r.text) > 100:
                    exposed_docs.append(path)
            except Exception:
                pass

        findings.append({
            "id": "A04",
            "name": "Diseño Inseguro — Documentación API Expuesta",
            "severity": "MEDIUM",
            "status": "VULNERABLE" if exposed_docs else "PASS",
            "details": f"Documentación API accesible: {', '.join(exposed_docs)}" if exposed_docs else "No se encontró documentación API expuesta.",
            "remediation": "Elimina o restringe el acceso a los endpoints de documentación API en producción. Protégelos con autenticación."
        })

        exposed_debug = []
        for path in DEBUG_ENDPOINTS:
            try:
                r = await client.get(target + path)
                if r.status_code in (200, 204):
                    exposed_debug.append(f"{path} → {r.status_code}")
            except Exception:
                pass

        findings.append({
            "id": "A04",
            "name": "Diseño Inseguro — Endpoints de Debug Expuestos",
            "severity": "HIGH",
            "status": "VULNERABLE" if exposed_debug else "PASS",
            "details": f"Endpoints de debug accesibles: {', '.join(exposed_debug)}" if exposed_debug else "No se encontraron endpoints de debug o actuator expuestos.",
            "remediation": "Deshabilita los endpoints de debug en producción. Usa variables de entorno para activarlos solo en desarrollo."
        })

        try:
            r = await client.get(target)
            server = r.headers.get("server", "")
            x_powered = r.headers.get("x-powered-by", "")
            match = VERSION_RE.search(server + " " + x_powered)
            findings.append({
                "id": "A04",
                "name": "Diseño Inseguro — Divulgación de Versión del Servidor",
                "severity": "MEDIUM",
                "status": "VULNERABLE" if match else "PASS",
                "details": f"Server: '{server}' | X-Powered-By: '{x_powered}'" if (server or x_powered) else "No se detectó información de versión.",
                "remediation": "Elimina u oculta los headers Server y X-Powered-By para evitar el fingerprinting del servidor."
            })
        except Exception:
            pass

    return findings
