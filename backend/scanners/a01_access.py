import httpx

ADMIN_PATHS = [
    "/admin", "/administrator", "/dashboard", "/wp-admin", "/wp-login.php",
    "/cpanel", "/.env", "/.git/config", "/config.php", "/backup",
    "/phpmyadmin", "/manager", "/console", "/admin.php"
]

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
    ("root", "root"), ("admin", ""), ("test", "test")
]

async def scan(target: str, mode: str) -> list:
    findings = []
    exposed = []

    async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
        for path in ADMIN_PATHS:
            try:
                r = await client.get(target + path)
                if r.status_code in (200, 401, 403):
                    exposed.append(f"{path} → HTTP {r.status_code}")
            except Exception:
                pass

    if exposed:
        findings.append({
            "id": "A01",
            "name": "Control de Acceso Deficiente",
            "severity": "HIGH",
            "status": "VULNERABLE",
            "details": f"Rutas sensibles encontradas: {', '.join(exposed)}",
            "remediation": "Restringe el acceso a rutas de administración. Devuelve 404 en lugar de 401/403 para evitar la enumeración de rutas."
        })
    else:
        findings.append({
            "id": "A01",
            "name": "Control de Acceso Deficiente",
            "severity": "HIGH",
            "status": "PASS",
            "details": "No se encontraron rutas de administración/sensibles expuestas.",
            "remediation": "Audita periódicamente los controles de acceso y restringe las rutas internas."
        })

    if mode == "active":
        login_paths = ["/admin/login", "/login", "/wp-login.php", "/admin"]
        for lpath in login_paths:
            for user, pwd in DEFAULT_CREDS:
                try:
                    async with httpx.AsyncClient(timeout=6, verify=False) as ac:
                        r = await ac.post(target + lpath, data={"username": user, "password": pwd, "user": user, "pass": pwd})
                        body = r.text.lower()
                        if r.status_code == 200 and any(k in body for k in ["dashboard", "logout", "welcome", "panel"]):
                            findings.append({
                                "id": "A01-ACTIVO",
                                "name": "Control de Acceso — Credenciales por Defecto",
                                "severity": "CRITICAL",
                                "status": "VULNERABLE",
                                "details": f"Login exitoso en {lpath} con {user}:{pwd}",
                                "remediation": "Cambia todas las credenciales por defecto de inmediato y habilita autenticación de dos factores."
                            })
                            return findings
                except Exception:
                    pass

    return findings
