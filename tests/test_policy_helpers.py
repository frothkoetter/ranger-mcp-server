from __future__ import annotations

import json

import pytest

from ranger_mcp_server.policy_helpers import (
    POLICY_TYPE_ACCESS,
    POLICY_TYPE_MASKING,
    build_access_policy_payload,
    build_masking_policy_payload,
    build_resource_map,
    build_tag_policy_payload,
    normalize_audit_resource_path,
    parse_csv,
    parse_json_object,
)


def test_parse_csv_empty() -> None:
    assert parse_csv("") == []
    assert parse_csv(None) == []


def test_normalize_audit_resource_path() -> None:
    assert normalize_audit_resource_path("db.table") == "db/table"
    assert normalize_audit_resource_path("db/table") == "db/table"
    assert normalize_audit_resource_path("mart_portfolio_risk_summary") == "mart_portfolio_risk_summary"
    assert normalize_audit_resource_path(None) is None


def test_parse_json_object() -> None:
    assert parse_json_object('{"database": {"values": ["finance"]}}')["database"]["values"] == ["finance"]


def test_parse_json_object_rejects_array() -> None:
    with pytest.raises(ValueError, match="must be a JSON object"):
        parse_json_object("[1, 2]")


def test_build_resource_map_from_simple_fields() -> None:
    resources = build_resource_map(None, database="finance", table="accounts")
    assert resources["database"]["values"] == ["finance"]
    assert resources["table"]["values"] == ["accounts"]


def test_build_resource_map_requires_input() -> None:
    with pytest.raises(ValueError, match="Provide resources_json"):
        build_resource_map(None)


def test_build_tag_policy_payload() -> None:
    policy = build_tag_policy_payload(
        tag_service_name="cm_tag",
        policy_name="pii-hive-select",
        tag_name="PII",
        access_type="hive:select",
        groups=["trusted_analysts"],
    )
    assert policy["service"] == "cm_tag"
    assert policy["policyType"] == POLICY_TYPE_ACCESS
    assert policy["resources"]["tag"]["values"] == ["PII"]
    assert policy["policyItems"][0]["accesses"][0]["type"] == "hive:select"
    assert policy["policyItems"][0]["groups"] == ["trusted_analysts"]


def test_build_access_policy_includes_roles() -> None:
    policy = build_access_policy_payload(
        "cm_hive",
        "role-policy",
        {"database": {"values": ["default"], "isExcludes": False, "isRecursive": False}},
        roles=["finance_role"],
        accesses=["select", "update"],
    )
    assert policy["policyItems"][0]["roles"] == ["finance_role"]
    assert len(policy["policyItems"][0]["accesses"]) == 2


def test_build_masking_policy_custom_expr() -> None:
    policy = build_masking_policy_payload(
        "cm_hive",
        "mask-custom",
        {"column": {"values": ["email"], "isExcludes": False, "isRecursive": False}},
        "CUSTOM",
        value_expr="mask_email({col})",
    )
    assert policy["policyType"] == POLICY_TYPE_MASKING
    assert policy["dataMaskPolicyItems"][0]["dataMaskInfo"]["valueExpr"] == "mask_email({col})"
