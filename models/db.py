from motor.motor_asyncio import AsyncIOMotorClient
import os

db = os.getenv("MONGO_URL")
if db is None:
    raise Exception("URL Not Found")

engine = AsyncIOMotorClient(db)