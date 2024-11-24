from pydantic import BaseModel, Field, EmailStr
from typing import Annotated

class UserRegister(BaseModel):
    username: Annotated[str, Field(max_length=20)]
    full_name: Annotated[str, Field()]
    email: EmailStr
    hashed_password: Annotated[str, Field()]

class UserLogin(BaseModel):
    username: Annotated[str, Field(max_length=20)]
    hashed_password: Annotated[str, Field()]

class Token(BaseModel):
    access_token : str
    token_type: str

class TokenData(BaseModel):
    username: Annotated[str, Field(max_length=20)]

class UserInDB(BaseModel):
    username: Annotated[str, Field(max_length=20)]
    full_name: Annotated[str, Field()]
    email: EmailStr
    hashed_password: Annotated[str, Field()]
