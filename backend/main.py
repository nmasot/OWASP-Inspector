from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Literal, List, Dict
import os
from fastapi.responses import StreamingResponse
from pdf_generator import generar_reporte_pdf
import io
from database import User, ScanHistory, get_db
from auth import crear_token_acceso, verificar_password, get_password_hash, obtener_usuario_actual
from scanners.orchestrator import run_all
from ai_engine import generar_mitigacion_ia

app = FastAPI(title="OWASP Inspector Engine", version="2.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str
    mode: Literal["passive", "active"] = "passive"
    consent: bool = False

class RegisterRequest(BaseModel):
    username: str
    password: str

class ScanReportRequest(BaseModel):
    target: str
    mode: str
    results: List[Dict]
    ai_plan: str

@app.post("/api/auth/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    existe = db.query(User).filter(User.username == req.username).first()
    if existe:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    nuevo_usuario = User(username=req.username, hashed_password=get_password_hash(req.password))
    db.add(nuevo_usuario)
    db.commit()
    return {"message": "Usuario creado con éxito"}

@app.post("/api/auth/token")
def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verificar_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Credenciales incorrectas")
    
    access_token = crear_token_acceso(data={"sub": user.username})
    
    # === BLINDAJE DEVSECOPS: INYECCIÓN DE COOKIE HTTPONLY ===
    # El navegador guardará esto automáticamente y JavaScript no podrá leerlo.
    response.set_cookie(
        key="access_token", 
        value=f"Bearer {access_token}", 
        httponly=True, 
        samesite="lax", 
        max_age=7200
    )
    return {"message": "Autenticación exitosa", "username": user.username}

@app.post("/api/auth/logout")
def logout(response: Response):
    """Destruye la cookie del navegador para cerrar la sesión de forma segura"""
    response.delete_cookie("access_token")
    return {"message": "Sesión cerrada correctamente"}

@app.get("/api/auth/me")
def get_me(current_user: str = Depends(obtener_usuario_actual)):
    return {"username": current_user, "status": "valid"}

@app.post("/api/scan")
async def start_scan(req: ScanRequest, current_user: str = Depends(obtener_usuario_actual), db: Session = Depends(get_db)):
    target = req.target
    if not target.startswith("http"):
        target = "http://" + target

    resultados = await run_all(target, req.mode)
    plan_ia = await generar_mitigacion_ia(resultados)

    crit = sum(1 for r in resultados if r.get("severity") in ["CRITICAL"] and r.get("status") == "VULNERABLE")
    high = sum(1 for r in resultados if r.get("severity") == "HIGH" and r.get("status") == "VULNERABLE")
    med = sum(1 for r in resultados if r.get("severity") == "MEDIUM" and r.get("status") == "VULNERABLE")

    user = db.query(User).filter(User.username == current_user).first()
    if user:
        nuevo = ScanHistory(target=target, mode=req.mode, critical_vulns=crit, high_vulns=high, medium_vulns=med, user_id=user.id)
        db.add(nuevo)
        db.commit()

    return {"target": target, "mode": req.mode, "ai_mitigation_plan": plan_ia, "results": resultados}

@app.get("/api/history")
def get_history(current_user: str = Depends(obtener_usuario_actual), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == current_user).first()
    return db.query(ScanHistory).filter(ScanHistory.user_id == user.id).order_by(ScanHistory.date.desc()).limit(20).all()

# --- NUEVOS ENDPOINTS DE ADMINISTRACIÓN ---
@app.delete("/api/history")
def clear_history(current_user: str = Depends(obtener_usuario_actual), db: Session = Depends(get_db)):
    if current_user != "admin":
        raise HTTPException(status_code=403, detail="Acceso denegado. Solo admin.")
    db.query(ScanHistory).delete()
    db.commit()
    return {"message": "Historial eliminado."}

@app.get("/api/users")
def list_users(current_user: str = Depends(obtener_usuario_actual), db: Session = Depends(get_db)):
    if current_user != "admin":
        raise HTTPException(status_code=403, detail="Acceso denegado. Solo admin.")
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username} for u in users]

@app.delete("/api/users/{username}")
def delete_user(username: str, current_user: str = Depends(obtener_usuario_actual), db: Session = Depends(get_db)):
    if current_user != "admin":
        raise HTTPException(status_code=403, detail="Acceso denegado.")
    if username == "admin":
        raise HTTPException(status_code=400, detail="No puedes borrar al admin principal.")
    u = db.query(User).filter(User.username == username).first()
    if u:
        db.query(ScanHistory).filter(ScanHistory.user_id == u.id).delete()
        db.delete(u)
        db.commit()
    return {"message": "Usuario eliminado"}

@app.put("/api/users/{username}")
def edit_user(username: str, req: RegisterRequest, current_user: str = Depends(obtener_usuario_actual), db: Session = Depends(get_db)):
    if current_user != "admin":
        raise HTTPException(status_code=403, detail="Acceso denegado.")
    u = db.query(User).filter(User.username == username).first()
    if not u:
        raise HTTPException(status_code=404, detail="No encontrado")
    u.hashed_password = get_password_hash(req.password)
    db.commit()
    return {"message": "Contraseña actualizada"}

@app.post("/api/scan/report-pdf")
async def generar_pdf_report(
    req: ScanReportRequest,
    current_user: str = Depends(obtener_usuario_actual)
):
    try:
        pdf_bytes = generar_reporte_pdf(
            target=req.target,
            mode=req.mode,
            resultados=req.results,
            plan_ia=req.ai_plan,
            auditor=current_user
        )
        
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=Audit_OWASP_{req.target.replace('/', '_')}.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generando PDF: {str(e)}")

# === MONTAJE DEL FRONTEND ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "frontend"))
app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")