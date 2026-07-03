import os
from datetime import datetime, timedelta
from fastapi import Request, HTTPException, status
from passlib.context import CryptContext
from dotenv import load_dotenv
import jwt

load_dotenv()

SECRET_KEY = os.environ.get("SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY no está definida. Crea un archivo .env con la variable o expórtala en tu entorno.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verificar_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def crear_token_acceso(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def obtener_usuario_actual(request: Request):
    # Ya no leemos headers, leemos directamente la cookie protegida
    token_str = request.cookies.get("access_token")
    
    if not token_str or not token_str.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="No autenticado o cookie ausente"
        )
    
    token = token_str.split(" ")[1]
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise Exception()
        return username
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado"
        )