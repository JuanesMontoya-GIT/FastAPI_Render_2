from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

import database, models, utils
from utils import verify_token

router = APIRouter()

# Modelos Pydantic para mejor validación
class UserRegister(BaseModel):
    name: Optional[str] = None
    email: str
    password: str
    role: Optional[str] = "cliente"


class UserLogin(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    id: int
    name: Optional[str]
    email: str
    role: str


class Token(BaseModel):
    access_token: str
    token_type: str


# -------- REGISTRAR USUARIO ----------
@router.post("/api/v1/auth/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserRegister, db: Session = Depends(database.get_db)):
    name = user_data.name
    email = user_data.email
    password = user_data.password
    role = user_data.role

    if not email or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email y password son requeridos"
        )

    # comprobación simple de formato de email
    if "@" not in email or "." not in email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email inválido"
        )

    existing = db.query(models.User).filter(models.User.email == email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El usuario ya existe"
        )

    # Hashear contraseña
    hashed = utils.hash_password(password)

    new_user = models.User(
        name=name,
        email=email,
        hashed_password=hashed,
        role=role
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return UserResponse(
        id=new_user.id,
        name=new_user.name,
        email=new_user.email,
        role=new_user.role
    )


# -------- LOGIN CON EMAIL Y PASSWORD ----------
@router.post("/api/v1/auth/login", response_model=Token)
def login(
        login_data: UserLogin,
        db: Session = Depends(database.get_db)
):
    user = db.query(models.User).filter(models.User.email == login_data.email).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas"
        )

    if not utils.verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas"
        )

    payload = {
        "user_id": user.id,
        "email": user.email,
        "role": user.role,
        "sub": user.email,
    }

    access_token = utils.create_access_token(data=payload)

    return Token(
        access_token=access_token,
        token_type="bearer"
    )


# -------- OBTENER USUARIO ACTUAL ----------
@router.get("/api/v1/auth/me", response_model=UserResponse)
def me(current_user: models.User = Depends(utils.get_current_user)):
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        name=current_user.name,
        role=current_user.role
    )


# =============================
# VALIDAR USUARIO DESDE OTROS MICROSERVICIOS
# =============================
@router.get("/api/v1/auth/validate-user/{user_id}")
def validate_user(
    user_id: int,
    token_data: dict = Depends(verify_token),
    db: Session = Depends(database.get_db)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    return {
        "valid": True,
        "user_id": user.id,
        "email": user.email,
        "role": user.role,
    }
