from typing import List
import os
import httpx

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from jose import jwt, JWTError

import database, models

router = APIRouter()

# Config
JWT_SECRET = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL")
PRODUCTS_SERVICE_URL = os.getenv("PRODUCTS_SERVICE_URL", "http://127.0.0.1:8003/api/v1/products")

security = HTTPBearer()

# -------------------------
# Pydantic models
# -------------------------
class OrderCreate(BaseModel):
    product_id: int = Field(..., gt=0)
    quantity: int = Field(..., gt=0)

    model_config = {"populate_by_name": True}


class OrderOut(BaseModel):
    id: int
    product_name: str
    product_price: float
    quantity: int
    total: float

    model_config = {"from_attributes": True}


# -------------------------
# DB dependency
# -------------------------
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -------------------------
# Token verification
# -------------------------
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        payload["token"] = token
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido o expirado")


async def verify_with_auth_service(user_id: int, token: str):
    url = f"{AUTH_SERVICE_URL}/validate-user/{user_id}"

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=10)

    if resp.status_code != 200:
        raise HTTPException(401, "Usuario no válido según auth_service")

    return resp.json()


async def get_product_from_products_service(product_id: int):
    url = f"{PRODUCTS_SERVICE_URL}/{product_id}"

    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=10)

    if resp.status_code == 404:
        raise HTTPException(404, "Producto no encontrado")
    if resp.status_code != 200:
        raise HTTPException(502, "Error consultando products_service")

    return resp.json()


# -------------------------
# Endpoints
# -------------------------

@router.post("/api/v1/orders", response_model=OrderOut, status_code=201)
async def create_order(
    order_req: OrderCreate,
    token_data: dict = Depends(verify_token),
    db: Session = Depends(get_db)
):
    await verify_with_auth_service(token_data["user_id"], token_data["token"])
    product = await get_product_from_products_service(order_req.product_id)

    name = product.get("name")
    price = float(product.get("price"))
    description = product.get("description", "")

    quantity = order_req.quantity
    total = price * quantity

    db_order = models.Order(
        user_id=token_data["user_id"],
        product_id=product.get("id"),
        product_name=name,
        product_price=price,
        product_description=description,
        quantity=quantity,
        total=total
    )

    db.add(db_order)
    db.commit()
    db.refresh(db_order)

    return {
        "id": db_order.id,
        "product_name": db_order.product_name,
        "product_price": db_order.product_price,
        "quantity": db_order.quantity,
        "total": db_order.total
    }


@router.get("/api/v1/orders", response_model=List[OrderOut])
async def list_orders(
    token_data: dict = Depends(verify_token),
    db: Session = Depends(get_db)
):
    await verify_with_auth_service(token_data["user_id"], token_data["token"])

    orders = db.query(models.Order).filter(models.Order.user_id == token_data["user_id"]).all()

    return [
        {
            "id": o.id,
            "product_name": o.product_name,
            "product_price": o.product_price,
            "quantity": o.quantity,
            "total": o.total
        }
        for o in orders
    ]


@router.get("/api/v1/orders/{order_id}", response_model=OrderOut)
async def get_order(
    order_id: int,
    token_data: dict = Depends(verify_token),
    db: Session = Depends(get_db)
):
    await verify_with_auth_service(token_data["user_id"], token_data["token"])

    order = db.query(models.Order).filter(models.Order.id == order_id).first()

    if not order:
        raise HTTPException(404, "Pedido no encontrado")

    if order.user_id != token_data["user_id"]:
        raise HTTPException(403, "Acceso denegado")

    return {
        "id": order.id,
        "product_name": order.product_name,
        "product_price": order.product_price,
        "quantity": order.quantity,
        "total": order.total
    }
