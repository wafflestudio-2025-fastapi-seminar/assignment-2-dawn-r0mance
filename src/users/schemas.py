import re

from pydantic import BaseModel, field_validator, EmailStr
from fastapi import HTTPException

from src.users.errors import InvalidPasswordException

class CreateUserRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone_number: str
    bio: str | None = None
    height: float

    @field_validator('password', mode='after')
    def validate_password(cls, v):
        if len(v) < 8 or len(v) > 20:
            raise InvalidPasswordException()
        return v
    
    @field_validator('phone_number', mode='after')
    def validate_phone_number(cls, v):
        num = r"^\d{3}-\d{4}-\d{4}$"
        if not re.fullmatch(num,v):
            raise ValueError("INVALID PHONE NUMBER")
        return v
    @field_validator('bio', mode='after')
    def validate_bio(cls, v):
        if len(v) > 500:
            raise ValueError("BIO TOO LONG")
        return v
class UserResponse(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    phone_number: str
    bio: str | None = None
    height: float

class user(BaseModel):
    user_id: int
    name: str
    email: EmailStr
    phone_number: str
    bio: str | None = None
    height: float
    hashed_password : str