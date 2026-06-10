import ipaddress
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, field_validator


class FirewallRuleRequest(BaseModel):
    ip: str
    expires_at: datetime

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        if "/" not in v:
            v = f"{v}/32"

        try:
            network = ipaddress.ip_network(v, strict=True)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {exc}") from exc

        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("Only IPv4 addresses are supported")

        if network.prefixlen != 32:
            raise ValueError("Only /32 IP addresses are allowed")

        if str(network.network_address) == "0.0.0.0":
            raise ValueError("IP address 0.0.0.0 is not allowed")

        return str(network)

    @field_validator("expires_at")
    @classmethod
    def validate_expiration(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        if v <= now:
            raise ValueError("expires_at must be in the future")

        if v > now + timedelta(hours=12):
            raise ValueError("expires_at cannot be more than 12 hours from now")

        return v


class FirewallRuleResponse(BaseModel):
    success: bool
    ip: str
    expires_at: str
    label: str
    message: str
