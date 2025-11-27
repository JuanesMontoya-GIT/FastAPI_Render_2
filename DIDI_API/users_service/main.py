from fastapi import FastAPI
import models, database
from routes import router
from utils import verify_token


app = FastAPI(
    title="Users Service",
    description="Microservicio de Gestión de Usuarios"
)

models.Base.metadata.create_all(bind=database.engine)

app.include_router(router)
