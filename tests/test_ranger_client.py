from __future__ import annotations

import pytest
from pytest_httpserver import HTTPServer

from ranger_mcp_server.client import RangerClient
from ranger_mcp_server.policy_helpers import build_tag_policy_payload


@pytest.fixture
def ranger(httpserver: HTTPServer) -> RangerClient:
    import requests

    session = requests.Session()
    return RangerClient(httpserver.url_for(""), session, timeout_seconds=5)


# ── Tag-based policies ───────────────────────────────────────────────────


def test_search_tag_policies_filtered_by_tag(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/public/v2/api/service/cm_tag/policy", method="GET").respond_with_json(
        [
            {
                "id": 42,
                "name": "pii-hive-select",
                "service": "cm_tag",
                "policyType": 0,
                "resources": {"tag": {"values": ["PII"], "isExcludes": False, "isRecursive": False}},
                "policyItems": [{"groups": ["trusted_analysts"]}],
            }
        ]
    )
    result = ranger.search_tag_policies("cm_tag", tag_name="PII")
    assert len(result) == 1
    assert result[0]["id"] == 42
    assert result[0]["resources"]["tag"]["values"] == ["PII"]


def test_search_tag_policies_all_on_tag_service(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/public/v2/api/service/cm_tag/policy", method="GET").respond_with_json(
        [
            {"id": 1, "name": "confidential-read", "resources": {"tag": {"values": ["Confidential"]}}},
            {"id": 2, "name": "pii-read", "resources": {"tag": {"values": ["PII"]}}},
        ]
    )
    result = ranger.search_tag_policies("cm_tag")
    assert len(result) == 2
    assert {p["name"] for p in result} == {"confidential-read", "pii-read"}


def test_search_tag_policies_pagination(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/public/v2/api/service/cm_tag/policy", method="GET").respond_with_json([])
    result = ranger.search_tag_policies("cm_tag", tag_name="PII", page_size=10, start_index=20)
    assert result == []


def test_create_tag_based_policy(ranger: RangerClient, httpserver: HTTPServer) -> None:
    policy = build_tag_policy_payload(
        tag_service_name="cm_tag",
        policy_name="pii-hdfs-read",
        tag_name="PII",
        access_type="hdfs:read",
        groups=["data_stewards"],
    )
    httpserver.expect_request("/public/v2/api/policy", method="POST").respond_with_json({"id": 99, **policy})
    result = ranger.create_policy(policy)
    assert result["id"] == 99
    assert result["resources"]["tag"]["values"] == ["PII"]
    assert result["policyItems"][0]["accesses"][0]["type"] == "hdfs:read"


def test_get_tag_definition_by_name(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/tags/tagdef/name/PII", method="GET").respond_with_json(
        {"id": 7, "name": "PII", "attributeDefs": []}
    )
    result = ranger.get_tag_definition_by_name("PII")
    assert result["name"] == "PII"


def test_list_tag_instances(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/tags/tags", method="GET").respond_with_json(
        [{"id": 1, "type": "PII", "isEnabled": True}]
    )
    result = ranger.list_tags()
    assert result[0]["type"] == "PII"


def test_list_tagged_resources_for_service(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/tags/resources/service/cm_hive", method="GET").respond_with_json(
        [{"serviceName": "cm_hive", "resourceElements": {"database": {"values": ["finance"]}}}]
    )
    result = ranger.list_tagged_resources(service_name="cm_hive")
    assert result[0]["serviceName"] == "cm_hive"


# ── General policies ─────────────────────────────────────────────────────


def test_search_policies(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/public/v2/api/service/cm_hive/policy", method="GET").respond_with_json(
        [{"id": 1, "name": "p1"}]
    )
    result = ranger.search_policies(service_name="cm_hive", policy_name_partial="p")
    assert result[0]["id"] == 1


def test_search_masking_policies_by_type(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/public/v2/api/service/cm_hive/policy", method="GET").respond_with_json(
        [{"id": 10, "name": "mask-ssn", "policyType": 1}]
    )
    result = ranger.search_policies(service_name="cm_hive", policy_type=1)
    assert result[0]["policyType"] == 1


def test_get_policy_by_name(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/public/v2/api/service/cm_hive/policy/finance-read", method="GET").respond_with_json(
        {"id": 5, "name": "finance-read", "service": "cm_hive"}
    )
    result = ranger.get_policy_by_name("cm_hive", "finance-read")
    assert result["id"] == 5


def test_get_policy_by_id(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/public/v2/api/policy/5", method="GET").respond_with_json(
        {"id": 5, "name": "policy-5"}
    )
    result = ranger.get_policy(5)
    assert result["name"] == "policy-5"


def test_apply_policy_upsert(ranger: RangerClient, httpserver: HTTPServer) -> None:
    policy = {"service": "cm_hive", "name": "upsert-policy", "policyType": 0, "resources": {}}
    httpserver.expect_request("/public/v2/api/policy/apply", method="POST").respond_with_json({"id": 77})
    result = ranger.apply_policy(policy)
    assert result["id"] == 77


def test_delete_policy_by_name(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/public/v2/api/policy", method="DELETE").respond_with_data("", status=200)
    result = ranger.delete_policy_by_name("cm_hive", "obsolete-policy")
    assert result == {} or result is not None


# ── Roles ────────────────────────────────────────────────────────────────


def test_create_role(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/public/v2/api/roles", method="POST").respond_with_json({"id": 5, "name": "r1"})
    result = ranger.create_role({"name": "r1", "isEnabled": True})
    assert result["id"] == 5


def test_add_users_and_groups_to_role(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/public/v2/api/roles/5/addUsersAndGroups", method="PUT").respond_with_json(
        {"id": 5, "name": "finance_role"}
    )
    result = ranger.add_users_and_groups_to_role(5, users=["alice"], groups=["analysts"])
    assert result["id"] == 5


def test_get_roles_for_user(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/public/v2/api/roles/user/alice", method="GET").respond_with_json(
        [{"id": 3, "name": "finance_role"}]
    )
    result = ranger.get_roles_for_user("alice")
    assert result[0]["name"] == "finance_role"


# ── Tags metadata ────────────────────────────────────────────────────────


def test_list_tag_definitions(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/tags/tagdefs", method="GET").respond_with_json([{"name": "PII"}])
    result = ranger.list_tag_definitions()
    assert result[0]["name"] == "PII"


# ── Users / groups ───────────────────────────────────────────────────────


def test_lookup_users(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/xusers/lookup/users", method="GET").respond_with_json(
        {"vXUsers": [{"name": "alice"}]}
    )
    result = ranger.lookup_users("ali")
    assert result["vXUsers"][0]["name"] == "alice"


def test_get_group_by_name(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/xusers/groups/groupName/analysts", method="GET").respond_with_json(
        {"id": 2, "name": "analysts"}
    )
    result = ranger.get_group_by_name("analysts")
    assert result["id"] == 2


# ── Access & admin audits ────────────────────────────────────────────────


def test_search_access_audits(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/xaudit/access_audit", method="GET").respond_with_json(
        {
            "vXAccessAudits": [
                {
                    "id": 100,
                    "requestUser": "alice",
                    "repoName": "cm_hive",
                    "accessResult": 1,
                    "resourcePath": "finance/customers",
                    "action": "select",
                }
            ],
            "totalCount": 1,
        }
    )
    result = ranger.search_access_audits(request_user="alice", repo_name="cm_hive")
    assert result["vXAccessAudits"][0]["requestUser"] == "alice"


def test_search_access_audits_assets_endpoint(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/assets/accessAudit", method="GET").respond_with_json(
        {"vXAccessAudits": [], "totalCount": 0}
    )
    result = ranger.search_access_audits(use_assets_endpoint=True, start_date="06/01/2026")
    assert result["totalCount"] == 0


def test_count_access_audits(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/xaudit/access_audit/count", method="GET").respond_with_json({"value": 42})
    result = ranger.count_access_audits(repo_name="cm_hive", access_result=0)
    assert result["value"] == 42


def test_search_admin_audit_logs(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/xaudit/trx_log", method="GET").respond_with_json(
        {
            "vXTrxLogs": [
                {
                    "id": 7,
                    "objectName": "finance-read",
                    "action": "update",
                    "updatedBy": "admin",
                }
            ],
            "totalCount": 1,
        }
    )
    result = ranger.search_admin_audit_logs(object_name="finance-read")
    assert result["vXTrxLogs"][0]["action"] == "update"


def test_count_admin_audit_logs(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/xaudit/trx_log/count", method="GET").respond_with_json({"value": 3})
    result = ranger.count_admin_audit_logs(updated_by="admin")
    assert result["value"] == 3


def test_get_admin_audit_log(ranger: RangerClient, httpserver: HTTPServer) -> None:
    httpserver.expect_request("/xaudit/trx_log/7", method="GET").respond_with_json(
        {"id": 7, "objectName": "finance-read", "action": "update"}
    )
    result = ranger.get_admin_audit_log(7)
    assert result["id"] == 7
