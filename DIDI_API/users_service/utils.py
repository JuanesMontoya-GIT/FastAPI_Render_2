# utils.py
from fastapi import HTTPException, status
from fastapi.security import HTTPBearer
from datetime import datetime, timedelta
from jose import jwt

security = HTTPBearer()

SECRET_KEY = "clave_super_secreta_cambia_esto_en_produccion"
ALGORITHM = "HS256"

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido"
        )
