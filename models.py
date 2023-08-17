from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class UserCreate(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    password:str

class User(BaseModel):
    id:int
    username: str
    email: str | None = None
    full_name: str | None = None

class UserInDB(User):
    hashed_password: str
