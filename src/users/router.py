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
from src.users.errors import (ExistedEmailException,
                            UnauthenticatedException,
                            InvalidAccountException,
                            InvalidTokenException)
from argon2 import PasswordHasher

user_router = APIRouter(prefix="/users", tags=["users"])
ph = PasswordHasher()
security = HTTPBearer(auto_error=False)

@user_router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(request: CreateUserRequest) -> UserResponse:
    
    if user_db != []:
        for u in user_db:
            if u.email == request.email:
                raise ExistedEmailException()
    
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
        if not session:
            raise UnauthenticatedException()

        now_ts = int(datetime.now(timezone.utc).timestamp())
        if session.get("expires_at") and session["expires_at"] < now_ts:
            session_db.pop(sid,None)
            raise UnauthenticatedException()

        user_id = int(session["user_id"])
        user = next((u for u in user_db if getattr(u, "user_id", None) == user_id), None)
        if not user:
            raise InvalidAccountException()
        return user 

    if creds in None or creds.scheme.lower() != "bearer":
        raise UnauthenticatedException()
    
    access_token = creds.credentials.strip()
    try:
        payload = jwt.decode(access_token, secret, algorithms=["HS256"])

        if payload.get("typ") and payload["typ"] != "access":
            raise InvalidTokenException()    
        user_id = int(payload["sub"])
    except jwt.ExpiredSignatureError:
        raise InvalidTokenException()
    except (jwt.InvalidTokenError, KeyError, ValueError, TypeError):
        raise InvalidTokenException()

    user = next((u for u in user_db if getattr(u, "user_id", None) == user_id), None)
    if not user:
        raise InvalidAccountException()

    return user



    