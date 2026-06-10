from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings

_bearer = HTTPBearer()


def verify_token(
    credentials: HTTPAuthorizationCredentials = Security(_bearer),
) -> str:
    if credentials.credentials != settings.api_token:
        raise HTTPException(status_code=401, detail="Invalid or missing API token")
    return credentials.credentials
