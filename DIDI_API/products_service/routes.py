import os
import httpx
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from jose import jwt
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models, database
from models import Product

router = APIRouter()

# =============================
# CONFIG JWT & AUTH SERVICE
# =============================
JWT_SECRET = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL")

security = HTTPBearer()


# =============================
# TOKEN VERIFICATION
# =============================
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        payload["token"] = token
        return payload
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido o expirado"
        )


async def verify_with_auth_service(user_id: int, token: str):
    """Valida el usuario contra el microservicio de AUTH."""
    url = f"{AUTH_SERVICE_URL}/validate-user/{user_id}"

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            url,
            headers={"Authorization": f"Bearer {token}"}
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no válido según auth_service"
        )

    return resp.json()


# =============================
# Pydantic Models
# =============================
class ProductCreate(BaseModel):
    name: str
    price: float
    description: str

    model_config = {"from_attributes": True}


class ProductOut(ProductCreate):
    id: int
    model_config = {"from_attributes": True}


# =============================
# Database dependency
# =============================
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =============================
# ROUTES
# =============================

# ----------- GET PRODUCTS (public)
@router.get("/api/v1/products", response_model=List[ProductOut])
def list_products(db: Session = Depends(get_db)):
    return db.query(Product).all()


@router.get("/api/v1/products/{product_id}", response_model=ProductOut)
def get_product(product_id: int, db: Session = Depends(get_db)):
    product = db.query(Product).filter(Product.id == product_id).first()

    if not product:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    return product


# ----------- CREATE PRODUCT (admin only)
@router.post(
    "/api/v1/products",
    response_model=ProductOut,
    status_code=status.HTTP_201_CREATED
)
async def create_product(
    product: ProductCreate,
    token_data: dict = Depends(verify_token),
    db: Session = Depends(get_db)
):

    # validar usuario en auth_service
    await verify_with_auth_service(token_data["user_id"], token_data["token"])

    # validar rol
    if token_data.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Solo un admin puede crear productos")

    # validaciones del producto
    if not product.name.strip():
        raise HTTPException(status_code=400, detail="El nombre no puede estar vacío")
    if product.price < 0:
        raise HTTPException(status_code=400, detail="El precio debe ser mayor o igual a 0")

    db_product = Product(
        name=product.name,
        price=product.price,
        description=product.description,
    )

    db.add(db_product)
    db.commit()
    db.refresh(db_product)

    return db_product


# ----------- UPDATE PRODUCT
@router.put("/api/v1/products/{product_id}", response_model=ProductOut)
async def update_product(
    product_id: int,
    data: dict,
    token_data: dict = Depends(verify_token),
    db: Session = Depends(get_db)
):
    # validar usuario
    await verify_with_auth_service(token_data["user_id"], token_data["token"])

    # validar rol
    if token_data.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Solo un admin puede actualizar productos")

    product = db.query(Product).filter(Product.id == product_id).first()

    if not product:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    # aplicar updates dinámicos
    for key, value in data.items():
        setattr(product, key, value)

    db.commit()
    db.refresh(product)

    return product


# ----------- DELETE PRODUCT
@router.delete("/api/v1/products/{product_id}")
async def delete_product(
    product_id: int,
    confirm: str = "",
    token_data: dict = Depends(verify_token),
    db: Session = Depends(get_db)
):

    # validar usuario
    await verify_with_auth_service(token_data["user_id"], token_data["token"])

    # validar rol
    if token_data.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Solo un admin puede eliminar productos")

    if confirm.lower() != "si":
        raise HTTPException(status_code=400, detail="Debes confirmar con 'si'")

    product = db.query(Product).filter(Product.id == product_id).first()

    if not product:
        raise HTTPException(status_code=404, detail="Producto no encontrado")

    db.delete(product)
    db.commit()

    return {"message": "Producto eliminado correctamente"}
