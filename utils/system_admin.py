from datetime import datetime, timedelta, timezone

import jwt.utils
from models.models import UserInDB
from utils.secrets import SECRET_KEY, ALGORITHM

import bcrypt
import jwt

# haz una función para verificacion de contraseña encriptada que codifique en 'utf-8'
def verify_password(plain_password: str, hashed_password: str) -> bool:
    password_byte_enc = plain_password.encode('utf-8')
    # Convertimos hashed_password a bytes si es una cadena de texto
    if isinstance(hashed_password, str):
        hashed_password = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password=password_byte_enc, hashed_password=hashed_password)


def get_password_hash(password) -> str:
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password=pwd_bytes, salt=salt)
    return hashed_password

def get_user(db, username:str):
    if username in db:
        user_dict= db[username]
        return UserInDB(**user_dict)
    
def authenticate_user(db, username: str, password:str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None=None):
    """
    Crea un token de acceso para un usuario.

    Args:
    - data (dict): Datos del usuario que se incluirán en el token.
    - expires_delta (timedelta, optional): Tiempo de expiración del token. Defaults to None.

    Returns:
    - str: Token de acceso creado.
    """
    
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
