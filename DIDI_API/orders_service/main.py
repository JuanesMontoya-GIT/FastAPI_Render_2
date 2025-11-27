from dotenv import load_dotenv
import os

# Cargar .env global (está en la raíz DIDI_API/.env)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))

from fastapi import FastAPI
from fastapi.security import HTTPBearer

import models, database
from routes import router

bearer_scheme = HTTPBearer()

app = FastAPI(title="Orders Service")

# Crear tablas
models.Base.metadata.create_all(bind=database.engine)

app.include_router(router)
