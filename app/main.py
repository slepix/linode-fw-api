import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.auth import verify_token
from app.config import settings
from app.linode import add_inbound_rule, delete_expired_rules
from app.models import FirewallRuleRequest, FirewallRuleResponse

logger = logging.getLogger(__name__)

_CLEANUP_INTERVAL = 600  # seconds


async def _cleanup_loop() -> None:
    while True:
        await asyncio.sleep(_CLEANUP_INTERVAL)
        try:
            removed = await delete_expired_rules()
            if removed:
                logger.info("Cleanup removed %d expired rule(s): %s", len(removed), removed)
            else:
                logger.debug("Cleanup: no expired rules found")
        except Exception:
            logger.exception("Cleanup cycle failed")


@asynccontextmanager
async def _lifespan(_app):
    task = asyncio.create_task(_cleanup_loop())
    yield
    task.cancel()


app = FastAPI(title="Linode Firewall API", version="1.0.0", lifespan=_lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://ai.cloud-instances.eu"],
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


def _make_label(ip: str, expires_at: datetime) -> str:
    # "1.2.3.4/32" -> "IP-1-2-3-4_<expiry_unix_ts>"
    host = ip.replace("/32", "").replace(".", "-")
    return f"IP-{host}_{int(expires_at.timestamp())}"


def _append_log(entry: dict) -> None:
    log_file = settings.log_file
    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)

    entries: list[dict] = []
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            try:
                entries = json.load(f)
            except (json.JSONDecodeError, ValueError):
                entries = []

    entries.append(entry)

    with open(log_file, "w") as f:
        json.dump(entries, f, indent=2)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/api/firewall/allow", response_model=FirewallRuleResponse, status_code=201)
async def allow_ip(
    request: FirewallRuleRequest,
    _token: str = Depends(verify_token),
) -> FirewallRuleResponse:
    label = _make_label(request.ip, request.expires_at)

    try:
        await add_inbound_rule(request.ip, label)
    except httpx.HTTPStatusError as exc:
        detail = exc.response.text or str(exc)
        raise HTTPException(status_code=502, detail=f"Linode API error: {detail}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Could not reach Linode API: {exc}") from exc

    _append_log(
        {
            "ip": request.ip,
            "expires_at": request.expires_at.isoformat(),
            "added_at": datetime.now(timezone.utc).isoformat(),
            "label": label,
            "firewall_id": settings.firewall_id,
        }
    )

    return FirewallRuleResponse(
        success=True,
        ip=request.ip,
        expires_at=request.expires_at.isoformat(),
        label=label,
        message=f"Rule added to firewall {settings.firewall_id}",
    )


@app.get("/api/firewall/log")
async def get_log(_token: str = Depends(verify_token)) -> JSONResponse:
    log_file = settings.log_file
    if not os.path.exists(log_file):
        return JSONResponse(content=[])

    with open(log_file, "r") as f:
        try:
            entries = json.load(f)
        except (json.JSONDecodeError, ValueError):
            entries = []

    return JSONResponse(content=entries)
