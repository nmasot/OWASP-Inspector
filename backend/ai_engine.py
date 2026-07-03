import os
import httpx
from dotenv import load_dotenv

load_dotenv()

api_key = os.environ.get("GEMINI_API_KEY")

if not api_key:
    raise RuntimeError("GEMINI_API_KEY no está definida. Crea un archivo .env con la variable o expórtala en tu entorno.")

async def generar_mitigacion_ia(hallazgos: list) -> str:
    criticos = [f for f in hallazgos if f.get("severity") in ["HIGH", "CRITICAL"]]
    
    if not criticos:
        return "No se detectaron vulnerabilidades de alto riesgo. Mantén las políticas actuales."
    prompt = f"Actúa como un Arquitecto DevSecOps. He escaneado mi infraestructura y encontré estas vulnerabilidades críticas: {criticos}. Proporciona un plan de mitigación directo y altamente técnico. Incluye estrategias de configuración y ejemplos conceptuales para corregir estos fallos. Sé conciso y omite introducciones genéricas."

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # =====================================================================
            # PASO 1: AUTO-DESCUBRIMIENTO (Consultamos los modelos disponibles)
            # =====================================================================
            url_list = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
            res_list = await client.get(url_list)
            
            if res_list.status_code != 200:
                return f"Error validando la API Key (HTTP {res_list.status_code}). Asegúrate de que la clave sea correcta."
            
            if res_list.status_code == 503:
                return "Servicio de IA temporalmente saturado. Reintenta en unos minutos."

            if res_list.status_code == 429:
                return "Se alcanzó el límite de solicitudes a la API. Reintenta más tarde."

            if res_list.status_code != 200:
                return f"Error validando la API Key (HTTP {res_list.status_code}). Asegúrate de que la clave sea correcta."
            
            modelos_permitidos = res_list.json().get("models", [])
            modelo_elegido = None
            
            # Buscamos dinámicamente el primer modelo que soporte "generateContent"
            for m in modelos_permitidos:
                nombre_modelo = m.get("name", "")
                metodos = m.get("supportedGenerationMethods", [])
                
                # Filtramos para asegurarnos de que sea un modelo de texto Gemini
                if "generateContent" in metodos and "gemini" in nombre_modelo.lower():
                    # Evitamos los modelos puramente visuales (vision)
                    if "vision" not in nombre_modelo.lower():
                        modelo_elegido = nombre_modelo
                        break

            if not modelo_elegido:
                return "La API Key es válida, pero no tienes modelos de generación de texto habilitados."

            # =====================================================================
            # PASO 2: GENERACIÓN DINÁMICA
            # =====================================================================
            url_gen = f"https://generativelanguage.googleapis.com/v1beta/{modelo_elegido}:generateContent?key={api_key}"
            payload = {"contents": [{"parts": [{"text": prompt}]}]}
            
            response = await client.post(url_gen, json=payload)
            
            if response.status_code != 200:
                return f"Error generando contenido con {modelo_elegido}: {response.text}"
                
            data = response.json()
            texto_ia = data["candidates"][0]["content"]["parts"][0]["text"]
            
            # Añadimos una pequeña firma para saber qué modelo auto-descubrió
            return f"[Generado dinámicamente por {modelo_elegido}]\n\n{texto_ia}"
            
    except Exception as e:
        return f"Error de conexión interna del servidor: {str(e)}"