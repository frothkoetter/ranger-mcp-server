from __future__ import annotations

from typing import Any, Dict, List, Optional

POLICY_TYPE_ACCESS = 0
POLICY_TYPE_MASKING = 1
POLICY_TYPE_ROW_FILTER = 2


def parse_csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def parse_json_object(raw: Optional[str], *, field_name: str = "json") -> Dict[str, Any]:
    if not raw or not raw.strip():
        return {}
    import json

    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError(f"{field_name} must be a JSON object")
    return parsed


def build_resource_map(resources_json: Optional[str], **simple_resources: Optional[str]) -> Dict[str, Any]:
    if resources_json:
        resources = parse_json_object(resources_json, field_name="resources_json")
    else:
        resources = {}
        for key, value in simple_resources.items():
            if value:
                resources[key] = {
                    "values": parse_csv(value),
                    "isExcludes": False,
                    "isRecursive": False,
                }
    if not resources:
        raise ValueError("Provide resources_json or at least one resource attribute (database, table, etc.)")
    return resources


def build_access_policy_payload(
    service_name: str,
    policy_name: str,
    resources: Dict[str, Any],
    users: Optional[List[str]] = None,
    groups: Optional[List[str]] = None,
    roles: Optional[List[str]] = None,
    accesses: Optional[List[str]] = None,
    description: str = "",
    is_enabled: bool = True,
) -> Dict[str, Any]:
    access_types = accesses or ["select"]
    return {
        "service": service_name,
        "name": policy_name,
        "policyType": POLICY_TYPE_ACCESS,
        "description": description,
        "isEnabled": is_enabled,
        "isAuditEnabled": True,
        "resources": resources,
        "policyItems": [
            {
                "accesses": [{"type": access, "isAllowed": True} for access in access_types],
                "users": users or [],
                "groups": groups or [],
                "roles": roles or [],
                "conditions": [],
                "delegateAdmin": False,
            }
        ],
        "denyPolicyItems": [],
        "allowExceptions": [],
        "denyExceptions": [],
        "dataMaskPolicyItems": [],
        "rowFilterPolicyItems": [],
    }


def build_masking_policy_payload(
    service_name: str,
    policy_name: str,
    resources: Dict[str, Any],
    data_mask_type: str,
    users: Optional[List[str]] = None,
    groups: Optional[List[str]] = None,
    value_expr: Optional[str] = None,
    description: str = "",
    is_enabled: bool = True,
) -> Dict[str, Any]:
    return {
        "service": service_name,
        "name": policy_name,
        "policyType": POLICY_TYPE_MASKING,
        "description": description,
        "isEnabled": is_enabled,
        "isAuditEnabled": True,
        "resources": resources,
        "policyItems": [],
        "dataMaskPolicyItems": [
            {
                "accesses": [{"type": "select", "isAllowed": True}],
                "users": users or ["*"],
                "groups": groups or [],
                "roles": [],
                "conditions": [],
                "delegateAdmin": False,
                "dataMaskInfo": {
                    "dataMaskType": data_mask_type,
                    "valueExpr": value_expr,
                    "conditionExpr": None,
                },
            }
        ],
        "rowFilterPolicyItems": [],
    }


def build_tag_policy_payload(
    tag_service_name: str,
    policy_name: str,
    tag_name: str,
    access_type: str,
    groups: Optional[List[str]] = None,
    users: Optional[List[str]] = None,
    description: str = "",
    is_enabled: bool = True,
) -> Dict[str, Any]:
    resources = {
        "tag": {"values": [tag_name], "isExcludes": False, "isRecursive": False},
    }
    return {
        "service": tag_service_name,
        "name": policy_name,
        "policyType": POLICY_TYPE_ACCESS,
        "description": description,
        "isEnabled": is_enabled,
        "isAuditEnabled": True,
        "resources": resources,
        "policyItems": [
            {
                "accesses": [{"type": access_type, "isAllowed": True}],
                "users": users or [],
                "groups": groups or [],
                "roles": [],
                "conditions": [],
                "delegateAdmin": False,
            }
        ],
        "dataMaskPolicyItems": [],
        "rowFilterPolicyItems": [],
    }
