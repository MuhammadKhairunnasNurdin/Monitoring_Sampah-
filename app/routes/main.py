# register all routes here
from fastapi import APIRouter

from app.routes import auth

api_router = APIRouter(prefix="/api", tags=["api"])
api_router.include_router(auth.router)
