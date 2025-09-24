from typing import Annotated
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import HTTPException
from fastapi import (
    APIRouter,
    Depends,
    Cookie,
    Header,
    status
)

from src.users.schemas import CreateUserRequest, UserResponse, user
from src.common.database import blocked_token_db, session_db, user_db
from argon2 import PasswordHasher

user_router = APIRouter(prefix="/users", tags=["users"])
ph = PasswordHasher()
security = HTTPBearer(auto_error=False)

@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    
    if user_db != []:
        for u in user_db:
            if u.email == request.email:
                raise ExistedEmailException
    
    userid = len(user_db) + 1
    user_db.append(
        user(
        user_id =  userid,
        email = request.email,
        hashed_password = ph.hash(request.password),
        name = request.name,
        phone_number = request.phone_number,
        height = request.height,
        bio = request.bio
        )
    )
    return UserResponse(
        user_id = userid,
        email = request.email,
        name = request.name,
        phone_number = request.phone_number,
        height = request.height,
        bio = request.bio
    )

    

@user_router.get("/me")
def get_user_info(
    sid: str | None = Cookie(default=None),
    creds: HTTPAuthorizationCredentials | None = Depends(security),
):
    if sid:
        session = session_db.get(sid)

        user_id = int(session["user_id"])

    elif creds:
        access_token = creds.credentials.strip()
        try:
            payload = jwt.decode(access_token, secret, algorithms=["HS256"])
            
            user_id = int(payload["sub"])
        except ExpiredSignatureError:
            raise HTTPException

        user = user_db[user_id - 1]

        return user



    