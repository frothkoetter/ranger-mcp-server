from __future__ import annotations

import pytest

from ranger_mcp_server.config import ServerConfig


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://host/topology/cdp-proxy-api/ranger",
            "https://host/topology/cdp-proxy-api/ranger/service",
        ),
        (
            "https://host/topology/cdp-proxy-api/ranger/",
            "https://host/topology/cdp-proxy-api/ranger/service",
        ),
        (
            "https://host/topology/cdp-proxy-api/ranger/service",
            "https://host/topology/cdp-proxy-api/ranger/service",
        ),
        (
            "https://host/topology/cdp-proxy-api/ranger/service/",
            "https://host/topology/cdp-proxy-api/ranger/service",
        ),
        (
            "https://ranger-host:6182/service",
            "https://ranger-host:6182/service",
        ),
    ],
)
def test_build_ranger_base_appends_service_when_missing(url: str, expected: str) -> None:
    config = ServerConfig(ranger_gateway_url=url)
    assert config.build_ranger_base() == expected


def test_build_ranger_base_requires_url() -> None:
    config = ServerConfig(ranger_gateway_url="")
    with pytest.raises(ValueError, match="RANGER_GATEWAY_URL must be set"):
        config.build_ranger_base()
