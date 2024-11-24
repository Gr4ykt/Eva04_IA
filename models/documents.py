from pydantic import Field, EmailStr
from typing import Annotated
from beanie import Document, Indexed

class User(Document):
    username: Annotated[str, Field(max_length=20), Indexed(unique=True)]
    full_name: Annotated[str, Field()]
    email: EmailStr
    hashed_password: Annotated[str, Field()]

    class Settings:
        name="Users"