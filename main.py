from datetime import datetime, timedelta
from decouple import config
from jose import JWTError, jwt
from passlib.context import CryptContext
from pymongo import MongoClient
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.encoders import jsonable_encoder

from auth import (authenticate_user,
                  create_access_token,
                  get_password_hash,
                  verify_password,
                  get_current_user,
                  get_user)
from databases import *
from models import Token, TokenData, User, UserInDB, UserCreate

import pdb

app = FastAPI()


ACCESS_TOKEN_EXPIRE_MINUTES = config('access_token_life_time')


@app.post("/token/", response_model=Token, tags=['users'])
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"username": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User, tags=['users'])
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)]
):
    return current_user


@app.post("/users/register/", status_code=status.HTTP_201_CREATED, tags=['users'])
async def register_new_user(user: UserCreate):
    userdb = get_user(user.username)
    if (userdb):
        raise HTTPException(
            status_code=409, detail="user with this username already exist!!!")

    if len(user.username) < 4:
        raise HTTPException(
            400, detail="username should be at least have 4 letter")
    elif len(user.password) < 4:
        raise HTTPException(
            400, detail="password should be at least have 4 letter widthr")

    user.password=get_password_hash(user.password)
    user_json=jsonable_encoder(user)
    result=users_collection.insert_one(user_json)
    return User(**user_json)
