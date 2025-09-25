from fastapi import APIRouter
from fastapi import Depends, Cookie
from fastapi import Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from datetime import datetime, timedelta, timezone
import secrets
from jwt import ExpiredSignatureError
import jwt

from src.common.database import blocked_token_db, session_db, user_db
from src.auth.schemas import LoginRequest
from src.users.errors import (
                            InvalidAccountException, 
                            InvalidTokenException, 
                            InvalidPasswordException,
                            BadAuthHeaderException,
                            UnauthenticatedException
                            )

auth_router = APIRouter(prefix="/auth", tags=["auth"])
ph = PasswordHasher()
secret = "my-secret-key"
security = HTTPBearer(auto_error=False)

SHORT_SESSION_LIFESPAN = 15
LONG_SESSION_LIFESPAN = 24 * 60

@auth_router.post("/token")
def outer(login: LoginRequest):
    for u in user_db:
        if login.email == u.email:
            try:
                ph.verify(u.hashed_password, login.password)
            except (VerifyMismatchError, VerificationError):
                raise InvalidAccountException()
            except Exception:
                raise InvalidAccountException()
            now = datetime.now(timezone.utc)
            access_payload = {
                "sub": str(u.user_id),
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(minutes= SHORT_SESSION_LIFESPAN)).timestamp())
            }
            refresh_payload = {
                "sub": str(u.user_id),
                 "iat": int(now.timestamp()),
                "exp": int((now + timedelta(minutes= LONG_SESSION_LIFESPAN)).timestamp())
            }
            access_token = jwt.encode(access_payload, secret, algorithm= "HS256")
            refresh_token = jwt.encode(refresh_payload, secret, algorithm= "HS256")
            return {
                "access_token": access_token,
                "refresh_token": refresh_token
            }
        
    raise InvalidAccountException()    
                
    

@auth_router.post("/token/refresh")
def p(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise UnauthenticatedException()
    
    if creds.scheme.lower() != "bearer":
        raise BadAuthHeaderException()

    old_refresh = creds.credentials.strip()

    if old_refresh in blocked_token_db:
        raise InvalidTokenException()
    
    try:
        oldref_payload = jwt.decode(old_refresh, secret, algorithms= ["HS256"])
        
        user_id = int(oldref_payload["sub"])

    except jwt.ExpiredSignatureError:
        blocked_token_db.add(old_refresh)
        raise InvalidTokenException()

    except (jwt.InvalidTokenError,KeyError, ValueError, TypeError):
        raise InvalidTokenException()

    blocked_token_db.add(old_refresh)
    now = datetime.now(timezone.utc)
    access_payload = {
        "sub" : str(user_id),
        "iat" : int(now.timestamp()),
        "exp" : int((now + timedelta(minutes= SHORT_SESSION_LIFESPAN)).timestamp())
    }
    refresh_payload = {
        "sub" : str(user_id),
        "iat" : int(now.timestamp()),
        "exp" : int((now + timedelta(minutes= LONG_SESSION_LIFESPAN)).timestamp())
    }
    access_token = jwt.encode(access_payload, secret, algorithm= "HS256")
    refresh_token = jwt.encode(refresh_payload, secret, algorithm= "HS256")

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }

@auth_router.delete("/token")
def d(creds: HTTPAuthorizationCredentials =  Depends(security)):
    if not creds:
        raise UnauthenticatedException()
    if creds.scheme.lower() != "bearer":
        raise BadAuthHeaderException()
    
    dead_refresh = creds.credentials.strip()

    if dead_refresh in blocked_token_db:
        return Response(status_code = 204)
    
    try:
        deadref_payload = jwt.decode(dead_refresh, secret, algorithms= ["HS256"])
        
        user_id = int(deadref_payload["sub"])

    except (jwt.InvalidTokenError, KeyError, ValueError, TypeError):
        raise InvalidTokenException()
    
    blocked_token_db.add(dead_refresh)
    
    return Response(status_code=204)

@auth_router.post("/session")
def p(login: LoginRequest):
    
    user = next((u for u in user_db if u.email == login.email), None)
    if not user:
        raise InvalidAccountException()
        
        try:
            ph.verify(u.hashed_password, login.password)
        except (VerifyMismatchError, VerificationError):
                raise InvalidAccountException()
        except Exception:
            raise InvalidAccountException()
                
        sid = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        exp_dt = now + timedelta(minutes=LONG_SESSION_LIFESPAN)
        exp_ts = int(exp_dt.timestamp())
                
        session_db[sid] = {
            "user_id": str(user.user_id),
            "created_at": int(now.timestamp()),
            "expires_at": exp_ts
        }
        response = Response(status_code=200)
        response.set_cookie(
            key="sid",
            value=session_id,
            max_age=LONG_SESSION_LIFESPAN * 60
        )

        return response
                

@auth_router.delete("/session")
def rd(sid: str | None = Cookie(default=None)):
    
    session_db.pop(sid,None)

    response = Response(status_code = 204)
    response.delete_cookie("sid")
    return response
    