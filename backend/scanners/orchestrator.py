import asyncio
from scanners import (
    a01_access, a02_misconfig, a03_supply_chain,
    a04_insecure_design, a05_injection, a06_crypto,
    a07_auth, a08_integrity, a09_logging, a10_exceptions
)

# Orden OWASP Top 10 (2025)
SCANNERS = [
    a01_access.scan,
    a02_misconfig.scan,
    a03_supply_chain.scan,
    a04_insecure_design.scan,
    a05_injection.scan,
    a06_crypto.scan,
    a07_auth.scan,
    a08_integrity.scan,
    a09_logging.scan,
    a10_exceptions.scan, # Nuevo motor 2025
]

async def run_all(target: str, mode: str) -> list:
    print(f"[*] Iniciando escaneo concurrente OWASP 2025 para: {target}")
    tasks = [scanner(target, mode) for scanner in SCANNERS]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    output = []
    for r in results:
        if isinstance(r, Exception):
            output.append({
                "id": "error",
                "name": "Scanner Error",
                "severity": "INFO",
                "status": "ERROR",
                "details": str(r),
                "remediation": "Revisar logs del backend. Posible falla de conexión."
            })
        elif isinstance(r, list):
            output.extend(r)
        elif isinstance(r, dict):
            output.append(r)
            
    return output