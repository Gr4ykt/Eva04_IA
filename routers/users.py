from fastapi import APIRouter, status, Depends, HTTPException
from fastapi.responses import JSONResponse
from beanie.operators import Or

from datetime import timedelta
from utils.get_utils import get_current_user, get_token

from models.Init import start_db
from models.models import UserRegister, Token, UserLogin, UserInDB
from models.documents import User
from utils.secrets import ACCESS_TOKEN_EXPIRE_MINUTES
from utils.system_admin import get_password_hash, create_access_token, verify_password

import logging

router = APIRouter()

# Buscar optimizaciones de codigo en el enpoint de registro
@router.post("/register_user")
async def register_user(register_user_data: UserRegister, start_session_db = Depends(start_db)):
    hashed_pwd = get_password_hash(register_user_data.hashed_password).decode('utf-8')
    username_on_db = await User.find(Or(User.username == register_user_data.username)).first_or_none()
    if username_on_db:
        raise HTTPException(
            {"reason": "Actualmente este usuario ya esta registrado"},
            status_code=status.HTTP_400_BAD_REQUEST
        )
    try:
        new_user = User(
            username=register_user_data.username,
            full_name=register_user_data.full_name,
            hashed_password= hashed_pwd,
            email= register_user_data.email
        )
    except Exception as e:
        logging.error(f"Error creating user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error creating user"
        )

    await new_user.insert()

    return JSONResponse(
        {"Success": "Usuario creado con exito", "username": new_user.username, "Nombre completo": new_user.full_name},
        status_code=status.HTTP_201_CREATED
    )

@router.post("/login")
async def login_user(user_login: UserLogin, start_session_db=Depends(start_db)) -> Token:
    user_in_db = await User.find_one(Or(User.username == user_login.username))
    if user_in_db is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid username or password"
        )
    if not verify_password(user_login.hashed_password, user_in_db.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid username or password"
        )
    
    # Generar el token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_in_db.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")

# curl -X GET "http://localhost:8000/me" -H "Authorization: bearer <Token>"
@router.get("/me", response_model=UserInDB)
async def me_detail(
    current_user: User = Depends(get_current_user),
    start_session_db=Depends(start_db),
    token: Token = Depends(get_token)
):
    return current_user

