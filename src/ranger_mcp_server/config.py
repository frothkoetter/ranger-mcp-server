from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class ServerConfig:
    transport: str = os.getenv("MCP_TRANSPORT", "stdio")
    host: str = os.getenv("MCP_HOST", "127.0.0.1")
    port: int = int(os.getenv("MCP_PORT", "3031"))

    # Ranger via Knox — full CDP gateway URL including /ranger/service
    # Example: RANGER_GATEWAY_URL=https://<host>/<topology>/cdp-proxy-api/ranger/service
    ranger_gateway_url: str = os.getenv("RANGER_GATEWAY_URL", "")

    ranger_user: Optional[str] = os.getenv("RANGER_USER") or os.getenv("ATLAS_USER")
    ranger_password: Optional[str] = os.getenv("RANGER_PASS") or os.getenv("ATLAS_PASS")

    knox_token: Optional[str] = os.getenv("KNOX_TOKEN")
    knox_cookie: Optional[str] = os.getenv("KNOX_COOKIE")

    verify_ssl_env: str = os.getenv("RANGER_VERIFY_SSL", os.getenv("ATLAS_VERIFY_SSL", "true")).lower()
    ca_bundle: Optional[str] = os.getenv("RANGER_CA_BUNDLE") or os.getenv("ATLAS_CA_BUNDLE")
    timeout_seconds: int = int(os.getenv("HTTP_TIMEOUT_SECONDS", "30"))
    max_retries: int = int(os.getenv("HTTP_MAX_RETRIES", "3"))

    def build_verify(self) -> bool | str:
        if self.ca_bundle:
            return self.ca_bundle
        return self.verify_ssl_env not in {"0", "false", "no"}

    def build_ranger_base(self) -> str:
        if not self.ranger_gateway_url:
            raise ValueError(
                "RANGER_GATEWAY_URL must be set.\n"
                "Example: RANGER_GATEWAY_URL=https://<host>/<topology>/cdp-proxy-api/ranger/service"
            )
        return self.ranger_gateway_url.rstrip("/")
