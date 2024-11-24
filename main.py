from fastapi import FastAPI, HTTPException
from routers import users

app = FastAPI()

app.include_router(users.router, prefix="", tags=["Users"])