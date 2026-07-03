import httpx
import re
import asyncio

# Patrones comunes de fugas de información en excepciones
EXCEPTION_PATTERNS = {
    "Python/Django": [r"Traceback \(most recent call last\)", r"TypeError:", r"NameError:", r"AttributeError:"],
    "Java/Spring": [r"java\.lang\.", r"org\.springframework\.", r"Internal Server Error", r"StackTrace"],
    "PHP": [r"Fatal error:", r"Uncaught Error:", r"require\(\): Failed opening", r"parse error"],
    "Node.js": [r"ReferenceError:", r"SyntaxError:", r"at\s+.*\s+\(.*\d+:\d+\)"],
    "ASP.NET": [r"System\.Web\.", r"System\.Data\.", r"HttpException", r"Stack Trace:"]
}

MALFORMED_INPUTS = [
    {"q": "'; DROP TABLE users; --"}, # Caracteres especiales
    {"id": "[][][]"},                 # Arrays malformados
    {"data": "{malformed_json:}"},    # JSON inválido
    {"file": "../../../etc/passwd"}   # Path traversal (fuerza errores de lectura)
]

async def scan(target: str, mode: str) -> list:
    findings = []
    
    async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
        # --- PRUEBA 1: Análisis de cabeceras de error (Pasivo) ---
        try:
            r = await client.get(target)
            server_header = r.headers.get("server", "").lower()
            if "debug" in server_header or "dev" in server_header:
                findings.append({
                    "id": "A10",
                    "name": "Excepciones — Cabeceras de Desarrollo",
                    "severity": "MEDIUM",
                    "status": "VULNERABLE",
                    "details": f"Se detectó un servidor en modo depuración (Server: {server_header}).",
                    "remediation": "Desactiva los headers de depuración en entornos de producción."
                })
        except Exception:
            pass

        # --- PRUEBA 2: Fuzzing de excepciones (Activo) ---
        if mode == "active":
            leaks_found = []
            for payload in MALFORMED_INPUTS:
                try:
                    # Enviamos entradas que suelen romper lógicas mal programadas
                    r = await client.get(target, params=payload)
                    
                    if r.status_code == 500:
                        body = r.text
                        for tech, patterns in EXCEPTION_PATTERNS.items():
                            for pattern in patterns:
                                if re.search(pattern, body, re.IGNORECASE):
                                    leaks_found.append(f"{tech} Stack Trace")
                                    break
                except Exception:
                    pass
            
            if leaks_found:
                findings.append({
                    "id": "A10-ACTIVO",
                    "name": "Excepciones — Fuga de Información Técnica",
                    "severity": "HIGH",
                    "status": "VULNERABLE",
                    "details": f"El servidor expuso detalles internos al fallar: {', '.join(set(leaks_found))}",
                    "remediation": "Implementa un manejador de errores global que capture todas las excepciones y devuelva mensajes genéricos."
                })
            else:
                findings.append({
                    "id": "A10-ACTIVO",
                    "name": "Excepciones — Manejo de Errores",
                    "severity": "HIGH",
                    "status": "PASS",
                    "details": "No se detectaron fugas de información técnica ante entradas malformadas.",
                    "remediation": "Sigue usando bloques try/except globales y páginas de error genéricas."
                })

    # Si no se encontró nada en pasivo y no se corrió activo
    if not findings:
        findings.append({
            "id": "A10",
            "name": "Manejo de Excepciones",
            "severity": "INFO",
            "status": "PASS",
            "details": "No se detectaron anomalías evidentes en el manejo de errores inicial.",
            "remediation": "Verifica manualmente que el modo 'debug' esté apagado en el backend."
        })

    return findings