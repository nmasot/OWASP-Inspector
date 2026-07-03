<div align="center">

<img src="https://img.shields.io/badge/OWASP-Top%2010%20(2025)-00f5ff?style=for-the-badge&logo=owasp&logoColor=white"/>
<img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
<img src="https://img.shields.io/badge/FastAPI-0.110-009688?style=for-the-badge&logo=fastapi&logoColor=white"/>
<img src="https://img.shields.io/badge/AI-Gemini-8A2BE2?style=for-the-badge&logo=google&logoColor=white"/>
<img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge"/>

<br/><br/>

```
  ██████╗ ██╗    ██╗ █████╗ ███████╗██████╗     ██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗ ██████╗ ██████╗ 
 ██╔═══██╗██║    ██║██╔══██╗██╔════╝██╔══██╗    ██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗
 ██║   ██║██║ █╗ ██║███████║███████╗██████╔╝    ██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   ██║   ██║██████╔╝
 ██║   ██║██║███╗██║██╔══██║╚════██║██╔═══╝     ██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗
 ╚██████╔╝╚███╔███╔╝██║  ██║███████║██║         ██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║
  ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝         ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
```

### Plataforma de Auditoría de Seguridad Web con IA Integrada
**Proyecto de Título · Ingeniería en Informática**

[Características](#-características) · [Arquitectura](#-arquitectura) · [Instalación](#-instalación) · [Uso](#-uso) · [Módulos OWASP](#-módulos-de-escaneo) · [API Reference](#-api-reference) · [Disclaimer](#%EF%B8%8F-disclaimer-legal)

</div>

---

## ¿Qué es OWASP Inspector?

**OWASP Inspector** es una plataforma full-stack de auditoría de seguridad web que automatiza la detección de vulnerabilidades según el estándar **OWASP Top 10 (2025)**. Dada la URL o IP de un objetivo, el motor ejecuta hasta **10 análisis de seguridad en paralelo**, clasifica los hallazgos por severidad (CRITICAL / HIGH / MEDIUM / LOW / INFO) y genera un **plan de mitigación técnico** usando inteligencia artificial (Google Gemini).

Diseñada para auditores de seguridad, pentesters y administradores de infraestructura que necesitan visibilidad rápida sobre la postura de seguridad de sus activos web.

---

## ✨ Características

| Capacidad | Descripción |
|---|---|
| 🔵 **Modo Pasivo** | Análisis no destructivo: headers HTTP, TLS, DNS, fingerprinting. Seguro en cualquier objetivo. |
| 🔴 **Modo Activo** | Inyección de payloads, fuerza bruta de credenciales por defecto, SSRF y pruebas de explotación profundas. Requiere consentimiento explícito. |
| 🤖 **Remediación IA** | El motor llama dinámicamente a Google Gemini con los hallazgos críticos y devuelve un plan de arquitectura DevSecOps personalizado. |
| 🔍 **Descubrimiento LAN** | Escaneo de redes por rango CIDR usando sockets TCP asíncronos puros (sin `nmap`, sin root). |
| 📊 **Historial de Auditorías** | Cada escaneo queda registrado en base de datos asociado al usuario autenticado. |
| 📄 **Exportación de Reportes** | Descarga del informe completo en formato JSON y PDF directamente desde el navegador. |
| 🔐 **Autenticación JWT** | Sistema de registro/login con tokens Bearer. Todos los endpoints de escaneo requieren sesión válida. |

---

## 🏗 Arquitectura

```
owasp-scanner/
├── backend/
│   ├── main.py                  # FastAPI: endpoints, CORS, montaje de frontend
│   ├── auth.py                  # JWT, bcrypt, OAuth2PasswordBearer
│   ├── database.py              # SQLAlchemy ORM: User, ScanHistory
│   ├── ai_engine.py             # Cliente Gemini con auto-descubrimiento de modelo
│   ├── lan_discovery.py         # Escaneo de red por rango CIDR
│   ├── requirements.txt
│   └── scanners/
│       ├── orchestrator.py      # asyncio.gather de los 10 módulos
│       ├── a01_access.py        # A01 — Broken Access Control
│       ├── a02_crypto.py        # A02 — Cryptographic Failures
│       ├── a03_injection.py     # A03 — Injection (XSS, SQLi)
│       ├── a04_insecure_design.py  # A04 — Insecure Design
│       ├── a05_misconfig.py     # A05 — Security Misconfiguration
│       ├── a06_components.py    # A06 — Vulnerable Components
│       ├── a07_auth.py          # A07 — Authentication Failures
│       ├── a08_integrity.py     # A08 — Software & Data Integrity
│       ├── a09_logging.py       # A09 — Security Logging Failures
│       └── a10_ssrf.py          # A10 — Server-Side Request Forgery
└── frontend/
    ├── index.html               # SPA — Tailwind CSS + FontAwesome
    └── script.js                # Lógica de UI, auth, scan, LAN, exportación
```

**Stack tecnológico:**

| Capa | Tecnología |
|---|---|
| Backend | Python 3.11 · FastAPI · Uvicorn (ASGI) |
| ORM / DB | SQLAlchemy 2.0 · SQLite |
| HTTP Client | `httpx` (async) |
| HTML Parsing | BeautifulSoup4 |
| Autenticación | JWT (PyJWT) · bcrypt (passlib) |
| IA | Google Gemini API (auto-discovery) |
| Frontend | HTML5 · Tailwind CSS · Vanilla JS |

---

## 🚀 Instalación

### Prerrequisitos

- Python 3.11 o superior
- `pip` y acceso a internet (para instalar dependencias y llamar a la API de Gemini)

### Pasos

```bash
# 1. Clonar el repositorio
git clone https://github.com/tu-usuario/owasp-inspector.git
cd owasp-inspector/backend

# 2. Crear y activar entorno virtual
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Configurar variables de entorno (opcional pero recomendado)
# Crea un archivo .env o expórtalas directamente:
export GEMINI_API_KEY="AIzaSy..."
export SECRET_KEY="tu_clave_secreta_segura"

# 5. Iniciar el servidor
python -m uvicorn main:app --reload --port 8000
```

El backend queda disponible en `http://127.0.0.1:8000`. El frontend se sirve automáticamente desde la misma URL gracias al montaje de archivos estáticos en FastAPI (`StaticFiles`).

> **Nota:** Para desarrollo, también puedes abrir `frontend/index.html` directamente o con Live Server de VS Code apuntando al puerto 8000.

---

## 🖥 Uso

### 1. Crear cuenta y autenticarse

Al acceder a `http://127.0.0.1:8000`, se muestra la pantalla de login. Regístrate con cualquier usuario y contraseña. Las credenciales se almacenan de forma segura con hash bcrypt.

> Credenciales de prueba por defecto: **admin / admin123**

### 2. Ejecutar un escaneo

1. Ingresa la URL o IP del objetivo (ej: `scanme.nmap.org`)
2. Selecciona el **modo de operación**:
   - 🔵 **Pasivo** — análisis de solo lectura, no afecta el servicio objetivo
   - 🔴 **Activo** — requiere marcar la casilla de consentimiento legal
3. Haz clic en **Iniciar Escaneo**
4. Los 10 módulos se ejecutan en paralelo. Los resultados aparecen con sus badges de severidad.
5. Si se detectan vulnerabilidades HIGH o CRITICAL, el panel de IA genera automáticamente un plan de remediación.

### 3. Descubrimiento LAN

1. Navega a la pestaña **🔍 Descubrimiento LAN**
2. Ingresa el rango CIDR de tu red (ej: `192.168.1.0/24`)
3. Haz clic en **Descubrir** — el motor enumera dispositivos con puertos HTTP abiertos
4. Usa el botón **🔍 Escanear OWASP** en cualquier dispositivo para analizarlo directamente

Para forzar resultados en pruebas locales, levanta un servidor en tu propia máquina:

```bash
python -m http.server 8080
```

### 4. Exportar resultados

Desde el panel de resultados, usa los botones:
- **JSON** — descarga el informe completo en formato JSON
- **Reporte PDF** — genera y descarga un reporte formateado

---

## 🔎 Módulos de Escaneo

Cada módulo implementa las verificaciones de una categoría OWASP. Todos devuelven un objeto con la estructura:

```json
{
  "id": "A03",
  "name": "Injection",
  "severity": "HIGH",
  "status": "VULNERABLE",
  "details": "Reflected XSS detectado en parámetro ?q=",
  "remediation": "Implementar Content-Security-Policy estricta..."
}
```

| ID | Categoría | Verificaciones Pasivas | Verificaciones Activas |
|---|---|---|---|
| A01 | Broken Access Control | Rutas admin expuestas (`/admin`, `/.env`, `/.git`) | POST con credenciales por defecto |
| A02 | Cryptographic Failures | Versión TLS, HSTS, redirección HTTPS | — |
| A03 | Injection | Patrones de error SQL en respuesta, análisis CSP | XSS reflejado, SQLi time-based |
| A04 | Insecure Design | Endpoints de documentación API y debug expuestos | — |
| A05 | Security Misconfiguration | Headers de seguridad faltantes, método TRACE | Ejecución de métodos peligrosos (PUT/DELETE) |
| A06 | Vulnerable Components | Fingerprinting de versiones EOL en headers | — |
| A07 | Authentication Failures | Flags de cookies, autocomplete, rate-limit | Fuerza bruta de formulario de login (3 intentos) |
| A08 | Software & Data Integrity | SRI en CDN scripts, CORS wildcard, CSP unsafe | — |
| A09 | Logging Failures | Logs y backups expuestos, `robots.txt` sensible | — |
| A10 | SSRF | Detección de parámetros `url`, `redirect`, `dest` | Inyección a `127.0.0.1` y metadata endpoint de cloud |

---

## 🤖 Motor de IA (Gemini)

El módulo `ai_engine.py` implementa un cliente con **auto-descubrimiento de modelos**:

1. Consulta el endpoint `/v1beta/models` de la API de Google para listar los modelos disponibles en la cuenta.
2. Selecciona dinámicamente el primer modelo `gemini` que soporte `generateContent` y no sea exclusivamente de visión.
3. Envía los hallazgos CRITICAL y HIGH como contexto a un prompt de rol **Arquitecto DevSecOps**.
4. Retorna el plan de mitigación con la firma del modelo que lo generó.

Esto garantiza compatibilidad automática con nuevos modelos de Gemini sin necesidad de cambiar el código.

---

## 📡 API Reference

Todos los endpoints de escaneo e historial requieren el header `Authorization: Bearer <token>`.

| Método | Endpoint | Auth | Descripción |
|---|---|---|---|
| `POST` | `/api/auth/register` | No | Registrar nuevo usuario |
| `POST` | `/api/auth/token` | No | Obtener JWT (form-data) |
| `GET` | `/api/auth/me` | Sí | Verificar sesión activa |
| `POST` | `/api/scan` | Sí | Ejecutar escaneo OWASP |
| `GET` | `/api/history` | Sí | Obtener historial del usuario |
| `POST` | `/api/lan/discover` | Sí | Escanear red LAN por CIDR |

**Cuerpo de `/api/scan`:**

```json
{
  "target": "https://ejemplo.com",
  "mode": "passive",
  "consent": false
}
```

> Si `mode == "active"` y `consent != true`, el servidor responde con HTTP 403.

---

## ⚙️ Variables de Entorno

| Variable | Por defecto | Descripción |
|---|---|---|
| `GEMINI_API_KEY` | *(hardcoded en dev)* | Clave de la API de Google Gemini |
| `SECRET_KEY` | `owasp_inspector_secret_2026` | Clave de firma JWT. **Cambiar en producción.** |

---

## ⚠️ Disclaimer Legal

> **Este software está diseñado exclusivamente para auditorías autorizadas.**
>
> El uso del **Modo Activo** genera tráfico de inyección y sondeos de explotación hacia el objetivo especificado. Ejecutarlo contra sistemas que no sean de tu propiedad o para los cuales no cuentes con **autorización escrita explícita** es ilegal en la mayoría de jurisdicciones y puede constituir un delito informático.
>
> Los autores de este proyecto no se responsabilizan por el uso indebido de esta herramienta. Úsala únicamente en entornos de prueba controlados, en tu propia infraestructura o con consentimiento documentado del propietario del sistema.

---

## 🔒 Consideraciones de Seguridad para Producción

- Reemplaza `SECRET_KEY` por un valor generado criptográficamente (`openssl rand -hex 32`)
- Almacena `GEMINI_API_KEY` en variables de entorno del sistema, nunca en el código fuente
- Configura CORS en `main.py` para permitir solo el origen exacto del frontend en lugar de `"*"`
- Considera migrar de SQLite a PostgreSQL para entornos multiusuario
- Agrega rate-limiting al endpoint `/api/scan` para prevenir abuso

---

## 📄 Licencia

Distribuido bajo la licencia **MIT**. Ver `LICENSE` para más detalles.

---

<div align="center">

Desarrollado como **Proyecto de Título** · TNS en Informática mención Ciberseguridad · 2026

*"La seguridad no es un producto, es un proceso."* — Bruce Schneier

</div>
