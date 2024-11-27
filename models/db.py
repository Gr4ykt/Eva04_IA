from motor.motor_asyncio import AsyncIOMotorClient
from utils.secrets import MONGO_URL

db = MONGO_URL
if db is None:
    raise Exception("URL Not Found")

engine = AsyncIOMotorClient(db)