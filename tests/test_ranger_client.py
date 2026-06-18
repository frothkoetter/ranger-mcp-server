from __future__ import annotations

import pytest
from pytest_httpserver import HTTPServer

from ranger_mcp_server.client import RangerClient
from ranger_mcp_server.policy_helpers import (
    build_access_policy_payload,
    build_masking_policy_payload,
    parse_csv,
)


@pytest.fixture
def ranger(httpserver: HTTPServer) -> RangerClient:
    import requests

    session = requests.Session()
    return RangerClient(httpserver.url_for(""), session, timeout_seconds=5)


def test_parse_csv() -> None:
    assert parse_csv("a, b") == ["a", "b"]


def test_build_access_policy() -> None:
    policy = build_access_policy_payload(
        "cm_hive",
        "test-policy",
        {"database": {"values": ["default"], "isExcludes": False, "isRecursive": False}},
        groups=["analysts"],
        accesses=["select"],
    )
    assert policy["service"] == "cm_hive"
    assert policy["policyType"] == 0


def test_search_policies(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/public/v2/api/service/cm_hive/policy", method="GET").respond_with_json(
        [{"id": 1, "name": "p1"}]
    )
    result = ranger.search_policies(service_name="cm_hive", policy_name_partial="p")
    assert result[0]["id"] == 1


def test_create_role(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/public/v2/api/roles", method="POST").respond_with_json({"id": 5, "name": "r1"})
    result = ranger.create_role({"name": "r1", "isEnabled": True})
    assert result["id"] == 5


def test_list_tag_definitions(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/tags/tagdefs", method="GET").respond_with_json([{"name": "PII"}])
    result = ranger.list_tag_definitions()
    assert result[0]["name"] == "PII"


def test_masking_policy_type() -> None:
    policy = build_masking_policy_payload(
        "cm_hive",
        "mask-ssn",
        {"column": {"values": ["ssn"], "isExcludes": False, "isRecursive": False}},
        "MASK",
    )
    assert policy["policyType"] == 1
    assert policy["dataMaskPolicyItems"]
