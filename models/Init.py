from fastapi import HTTPException, status
from models.documents import User
from models.db import engine
from beanie import init_beanie

async def start_db():
    try:
        await init_beanie(engine["mongo_api"], document_models=[User])
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database initialization error"
        )
