from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, validator
from sqlalchemy.orm import Session
from passlib.context import CryptContext

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

import models, database

router = APIRouter()

# ==========================
# 🔐 Configuración de Seguridad
# ==========================
security = HTTPBearer()

SECRET_KEY = "clave_super_secreta_cambia_esto_en_produccion"  # cámbiala luego
ALGORITHM = "HS256"


# ==========================
# 🔐 Verificar token desde el HEADER Authorization: Bearer <token>
# ==========================
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado",
            headers={"WWW-Authenticate": "Bearer"}
        )


# ==========================
# 👤 Obtener usuario autenticado
# ==========================
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    return verify_token(credentials)


# ==========================
# 🔐 Validación de roles (Solo Admin)
# ==========================
def allow_admin(token_data: dict = Depends(verify_token)):
    if token_data.get("role") != "admin":
        raise HTTPException(
            status_code=403,
            detail="No autorizado. Solo un usuario con rol 'admin' puede realizar esta acción."
        )
    return token_data


# ==========================
# 🧱 Modelos internos Pydantic
# ==========================
class UserCreate(BaseModel):
    name: Optional[str] = None
    email: EmailStr
    password: str
    role: Optional[str] = "cliente"
    model_config = {"from_attributes": True}

    @validator("email")
    def validar_email(cls, v):
        if "@" not in v:
            raise ValueError("El email debe contener un '@'.")
        return v

    @validator("password")
    def validar_password(cls, v):
        if not v or len(v.strip()) == 0:
            raise ValueError("La contraseña no puede estar vacía.")
        if len(v) < 6:
            raise ValueError("La contraseña debe tener al menos 6 caracteres.")
        return v

    @validator("name")
    def validar_nombre(cls, v):
        if v is not None and len(v.strip()) == 0:
            raise ValueError("El nombre no puede estar vacío.")
        return v


class UserOut(BaseModel):
    id: int
    name: Optional[str] = None
    email: EmailStr
    role: str
    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    role: Optional[str] = None
    model_config = {"from_attributes": True}


# ==========================
# 🔧 Dependencia de DB
# ==========================
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==========================
# 🔐 Utilidad para encriptar
# ==========================
def hash_password(password: str):
    password = password[:72]
    return pwd_context.hash(password)


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ==========================
# 🚀 Endpoints SOLO PARA ADMIN (con token en Header)
# ==========================

@router.post("/api/v1/users/create", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    user: UserCreate,
    token_data: dict = Depends(allow_admin),
    db: Session = Depends(get_db)
):
    if not user.email or not user.password:
        raise HTTPException(status_code=400, detail="Los campos email y contraseña son obligatorios.")

    existing = db.query(models.User).filter(models.User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="El email ya está registrado.")

    hashed_pw = hash_password(user.password)

    db_user = models.User(
        name=user.name,
        email=user.email,
        hashed_password=hashed_pw,
        role=user.role or "cliente"
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@router.get("/api/v1/users", response_model=List[UserOut])
def list_users(
    token_data: dict = Depends(allow_admin),
    db: Session = Depends(get_db)
):
    return db.query(models.User).all()


@router.get("/api/v1/users/{user_id}", response_model=UserOut)
def get_user(
    user_id: int,
    token_data: dict = Depends(allow_admin),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")
    return user


@router.put("/api/v1/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    update: UserUpdate,
    token_data: dict = Depends(allow_admin),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")

    if update.email:
        existing = db.query(models.User).filter(models.User.email == update.email, models.User.id != user_id).first()
        if existing:
            raise HTTPException(status_code=400, detail="El email ya está en uso por otro usuario.")
        user.email = update.email

    if update.name is not None:
        if len(update.name.strip()) == 0:
            raise HTTPException(status_code=400, detail="El nombre no puede estar vacío.")
        user.name = update.name

    if update.role is not None:
        user.role = update.role

    if update.password is not None:
        if len(update.password) < 6:
            raise HTTPException(status_code=400, detail="La contraseña debe tener al menos 6 caracteres.")
        user.hashed_password = hash_password(update.password)

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.delete("/api/v1/users/{user_id}")
def delete_user(
    user_id: int,
    token_data: dict = Depends(allow_admin),
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado.")
    db.delete(user)
    db.commit()
    return {"message": "Usuario eliminado correctamente."}
