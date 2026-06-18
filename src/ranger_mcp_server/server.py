from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

import anyio

from .auth import RangerAuthFactory
from .client import RangerClient
from .config import ServerConfig
from .policy_helpers import (
    build_access_policy_payload,
    build_masking_policy_payload,
    build_resource_map,
    build_tag_policy_payload,
    parse_csv,
    parse_json_object,
)

try:
    from mcp.server import FastMCP
except Exception as e:
    raise RuntimeError("The 'mcp' package is required. Install with: pip install mcp") from e


def _redact(obj: Any, max_items: int = 200) -> Any:
    _SENSITIVE = {"password", "passcode", "token", "secret", "passwd"}
    if isinstance(obj, dict):
        return {
            k: "***REDACTED***" if k.lower() in _SENSITIVE else _redact(v, max_items)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        if len(obj) > max_items:
            return [_redact(x, max_items) for x in obj[:max_items]] + [
                {"truncated": True, "omitted_count": len(obj) - max_items}
            ]
        return [_redact(x, max_items) for x in obj]
    return obj


def build_client(config: ServerConfig) -> RangerClient:
    verify = config.build_verify()
    base_url = config.build_ranger_base()
    auth = RangerAuthFactory(
        user=config.ranger_user,
        password=config.ranger_password,
        knox_token=config.knox_token,
        knox_cookie=config.knox_cookie,
        verify=verify,
    )
    session = auth.build_session()
    return RangerClient(base_url, session, timeout_seconds=config.timeout_seconds)


def create_server(ranger: RangerClient) -> FastMCP:
    app = FastMCP("ranger-mcp-server")

    # ── Services ───────────────────────────────────────────────────────────

    @app.tool()
    async def list_ranger_services(
        page_size: int = 25,
        start_index: int = 0,
        service_name: Optional[str] = None,
        service_type: Optional[str] = None,
    ) -> Any:
        """List Ranger service instances (cm_hive, cm_hdfs, cm_tag, etc.)."""
        return _redact(
            ranger.list_services(
                page_size=page_size,
                start_index=start_index,
                service_name=service_name,
                service_type=service_type,
            )
        )

    @app.tool()
    async def get_ranger_service(service_name: str) -> Dict[str, Any]:
        """Get a Ranger service instance by name."""
        return _redact(ranger.get_service_by_name(service_name))

    @app.tool()
    async def get_ranger_service_definition(service_type: str) -> Dict[str, Any]:
        """Get the service definition schema (access types, resources, mask types) for a component type."""
        return _redact(ranger.get_service_def_by_name(service_type))

    # ── Policies ───────────────────────────────────────────────────────────

    @app.tool()
    async def search_ranger_policies(
        service_name: Optional[str] = None,
        policy_name: Optional[str] = None,
        policy_name_partial: Optional[str] = None,
        user: Optional[str] = None,
        group: Optional[str] = None,
        policy_type: Optional[int] = None,
        page_size: int = 25,
        start_index: int = 0,
    ) -> Any:
        """Search Ranger policies. policy_type: 0=access, 1=masking, 2=row-filter."""
        return _redact(
            ranger.search_policies(
                service_name=service_name,
                policy_name=policy_name,
                policy_name_partial=policy_name_partial,
                user=user,
                group=group,
                policy_type=policy_type,
                page_size=page_size,
                start_index=start_index,
            )
        )

    @app.tool()
    async def get_ranger_policy(
        policy_id: Optional[int] = None,
        service_name: Optional[str] = None,
        policy_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get a policy by id or by service_name + policy_name."""
        if policy_id is not None:
            return _redact(ranger.get_policy(policy_id))
        if service_name and policy_name:
            return _redact(ranger.get_policy_by_name(service_name, policy_name))
        return {"error": "Provide policy_id or both service_name and policy_name"}

    @app.tool()
    async def create_ranger_policy(policy_json: str) -> Dict[str, Any]:
        """Create a Ranger policy from a full JSON payload. **WRITE OPERATION**"""
        policy = parse_json_object(policy_json, field_name="policy_json")
        return _redact(ranger.create_policy(policy))

    @app.tool()
    async def update_ranger_policy(policy_id: int, policy_json: str) -> Dict[str, Any]:
        """Update an existing Ranger policy by id. **WRITE OPERATION**"""
        policy = parse_json_object(policy_json, field_name="policy_json")
        return _redact(ranger.update_policy(policy_id, policy))

    @app.tool()
    async def apply_ranger_policy(policy_json: str) -> Dict[str, Any]:
        """Create or update a policy via the apply/upsert endpoint. **WRITE OPERATION**"""
        policy = parse_json_object(policy_json, field_name="policy_json")
        return _redact(ranger.apply_policy(policy))

    @app.tool()
    async def delete_ranger_policy(
        policy_id: Optional[int] = None,
        service_name: Optional[str] = None,
        policy_name: Optional[str] = None,
    ) -> Any:
        """Delete a policy by id or by service_name + policy_name. **WRITE OPERATION**"""
        if policy_id is not None:
            return _redact(ranger.delete_policy_by_id(policy_id))
        if service_name and policy_name:
            return _redact(ranger.delete_policy_by_name(service_name, policy_name))
        return {"error": "Provide policy_id or both service_name and policy_name"}

    @app.tool()
    async def create_access_policy(
        service_name: str,
        policy_name: str,
        users: Optional[str] = None,
        groups: Optional[str] = None,
        roles: Optional[str] = None,
        accesses: str = "select",
        database: Optional[str] = None,
        table: Optional[str] = None,
        column: Optional[str] = None,
        path: Optional[str] = None,
        resources_json: Optional[str] = None,
        description: str = "",
    ) -> Dict[str, Any]:
        """Create an access-control policy. **WRITE OPERATION**

        Provide resources via resources_json or simple fields (database, table, column, path).
        users/groups/roles/accesses are comma-separated.
        """
        resources = build_resource_map(resources_json, database=database, table=table, column=column, path=path)
        policy = build_access_policy_payload(
            service_name=service_name,
            policy_name=policy_name,
            resources=resources,
            users=parse_csv(users),
            groups=parse_csv(groups),
            roles=parse_csv(roles),
            accesses=parse_csv(accesses),
            description=description,
        )
        return _redact(ranger.create_policy(policy))

    @app.tool()
    async def create_masking_policy(
        service_name: str,
        policy_name: str,
        data_mask_type: str,
        users: Optional[str] = None,
        groups: Optional[str] = None,
        database: Optional[str] = None,
        table: Optional[str] = None,
        column: Optional[str] = None,
        resources_json: Optional[str] = None,
        value_expr: Optional[str] = None,
        description: str = "",
    ) -> Dict[str, Any]:
        """Create a data-masking policy (policyType=1). **WRITE OPERATION**

        data_mask_type examples: MASK, MASK_SHOW_LAST_4, MASK_HASH, MASK_NULL, CUSTOM.
        """
        resources = build_resource_map(resources_json, database=database, table=table, column=column)
        policy = build_masking_policy_payload(
            service_name=service_name,
            policy_name=policy_name,
            resources=resources,
            data_mask_type=data_mask_type,
            users=parse_csv(users),
            groups=parse_csv(groups),
            value_expr=value_expr,
            description=description,
        )
        return _redact(ranger.create_policy(policy))

    @app.tool()
    async def create_tag_based_policy(
        tag_service_name: str,
        policy_name: str,
        tag_name: str,
        access_type: str,
        groups: Optional[str] = None,
        users: Optional[str] = None,
        description: str = "",
    ) -> Dict[str, Any]:
        """Create a tag-based access policy on the tag service (e.g. cm_tag). **WRITE OPERATION**

        access_type is prefixed by target service, e.g. hive:select or hdfs:read.
        """
        policy = build_tag_policy_payload(
            tag_service_name=tag_service_name,
            policy_name=policy_name,
            tag_name=tag_name,
            access_type=access_type,
            groups=parse_csv(groups),
            users=parse_csv(users),
            description=description,
        )
        return _redact(ranger.create_policy(policy))

    # ── Roles ────────────────────────────────────────────────────────────

    @app.tool()
    async def list_ranger_roles(page_size: int = 25, start_index: int = 0) -> Any:
        """List Ranger policy-engine roles."""
        return _redact(ranger.list_roles(page_size=page_size, start_index=start_index))

    @app.tool()
    async def get_ranger_role(
        role_id: Optional[int] = None,
        role_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get a role by id or name."""
        if role_id is not None:
            return _redact(ranger.get_role(role_id))
        if role_name:
            return _redact(ranger.get_role_by_name(role_name))
        return {"error": "Provide role_id or role_name"}

    @app.tool()
    async def create_ranger_role(
        role_name: str,
        description: str = "",
        users: Optional[str] = None,
        groups: Optional[str] = None,
        service_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a Ranger role with optional members. **WRITE OPERATION**"""
        role = {
            "name": role_name,
            "description": description,
            "isEnabled": True,
            "users": [{"name": n, "isAdmin": False} for n in parse_csv(users)],
            "groups": [{"name": n, "isAdmin": False} for n in parse_csv(groups)],
            "roles": [],
        }
        return _redact(ranger.create_role(role, service_name=service_name))

    @app.tool()
    async def update_ranger_role(role_id: int, role_json: str) -> Dict[str, Any]:
        """Update a Ranger role from JSON. **WRITE OPERATION**"""
        return _redact(ranger.update_role(role_id, parse_json_object(role_json, field_name="role_json")))

    @app.tool()
    async def delete_ranger_role(role_id: int) -> Any:
        """Delete a Ranger role by id. **WRITE OPERATION**"""
        return _redact(ranger.delete_role(role_id))

    @app.tool()
    async def add_users_groups_to_role(
        role_id: int,
        users: Optional[str] = None,
        groups: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add users and/or groups to an existing role. **WRITE OPERATION**"""
        return _redact(
            ranger.add_users_and_groups_to_role(
                role_id=role_id,
                users=parse_csv(users),
                groups=parse_csv(groups),
            )
        )

    @app.tool()
    async def get_roles_for_user(user_name: str) -> Any:
        """List roles assigned to a user."""
        return _redact(ranger.get_roles_for_user(user_name))

    # ── Users & groups ─────────────────────────────────────────────────────

    @app.tool()
    async def list_ranger_users(page_size: int = 25, start_index: int = 0) -> Any:
        """List Ranger users."""
        return _redact(ranger.list_users(page_size=page_size, start_index=start_index))

    @app.tool()
    async def get_ranger_user(user_name: str) -> Dict[str, Any]:
        """Get a Ranger user by name."""
        return _redact(ranger.get_user_by_name(user_name))

    @app.tool()
    async def create_ranger_user(
        user_name: str,
        password: Optional[str] = None,
        first_name: str = "",
        last_name: str = "",
        user_roles: str = "ROLE_USER",
        group_ids: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a Ranger user. **WRITE OPERATION**

        user_roles: ROLE_USER or ROLE_SYS_ADMIN. group_ids: comma-separated numeric ids.
        """
        user: Dict[str, Any] = {
            "name": user_name,
            "firstName": first_name or user_name,
            "lastName": last_name or user_name,
            "loginId": user_name,
            "status": 1,
            "isVisible": 1,
            "userSource": 0,
            "userRoleList": parse_csv(user_roles) or ["ROLE_USER"],
        }
        if password:
            user["password"] = password
        if group_ids:
            user["groupIdList"] = [int(g) for g in parse_csv(group_ids)]
        return _redact(ranger.create_user(user))

    @app.tool()
    async def update_ranger_user(user_id: int, user_json: str) -> Dict[str, Any]:
        """Update a Ranger user from JSON. **WRITE OPERATION**"""
        return _redact(ranger.update_user(user_id, parse_json_object(user_json, field_name="user_json")))

    @app.tool()
    async def delete_ranger_user(user_id: int) -> Any:
        """Delete a Ranger user by id. **WRITE OPERATION**"""
        return _redact(ranger.delete_user(user_id))

    @app.tool()
    async def list_ranger_groups(page_size: int = 25, start_index: int = 0) -> Any:
        """List Ranger groups."""
        return _redact(ranger.list_groups(page_size=page_size, start_index=start_index))

    @app.tool()
    async def get_ranger_group(group_name: str) -> Dict[str, Any]:
        """Get a Ranger group by name."""
        return _redact(ranger.get_group_by_name(group_name))

    @app.tool()
    async def create_ranger_group(group_name: str, description: str = "") -> Dict[str, Any]:
        """Create a Ranger group. **WRITE OPERATION**"""
        group = {"name": group_name, "description": description, "isVisible": 1}
        return _redact(ranger.create_group(group))

    @app.tool()
    async def update_ranger_group(group_id: int, group_json: str) -> Dict[str, Any]:
        """Update a Ranger group from JSON. **WRITE OPERATION**"""
        return _redact(ranger.update_group(group_id, parse_json_object(group_json, field_name="group_json")))

    @app.tool()
    async def delete_ranger_group(group_id: int) -> Any:
        """Delete a Ranger group by id. **WRITE OPERATION**"""
        return _redact(ranger.delete_group(group_id))

    @app.tool()
    async def lookup_ranger_users(name: str) -> Any:
        """Search Ranger users by partial name."""
        return _redact(ranger.lookup_users(name))

    @app.tool()
    async def lookup_ranger_groups(name: str) -> Any:
        """Search Ranger groups by partial name."""
        return _redact(ranger.lookup_groups(name))

    # ── Tags ───────────────────────────────────────────────────────────────

    @app.tool()
    async def list_tag_definitions() -> Any:
        """List Ranger tag type definitions."""
        return _redact(ranger.list_tag_definitions())

    @app.tool()
    async def get_tag_definition(tag_name: str) -> Dict[str, Any]:
        """Get a tag definition by name."""
        return _redact(ranger.get_tag_definition_by_name(tag_name))

    @app.tool()
    async def list_tag_instances() -> Any:
        """List tag instances in Ranger."""
        return _redact(ranger.list_tags())

    @app.tool()
    async def list_tagged_resources(service_name: Optional[str] = None) -> Any:
        """List resources that have tags applied."""
        return _redact(ranger.list_tagged_resources(service_name=service_name))

    @app.tool()
    async def search_tag_based_policies(
        tag_service_name: str,
        tag_name: Optional[str] = None,
        page_size: int = 25,
        start_index: int = 0,
    ) -> Any:
        """Search tag-based policies on the tag service (e.g. cm_tag)."""
        return _redact(
            ranger.search_tag_policies(
                tag_service_name=tag_service_name,
                tag_name=tag_name,
                page_size=page_size,
                start_index=start_index,
            )
        )

    # ── Audits ─────────────────────────────────────────────────────────────

    @app.tool()
    async def search_access_audits(
        page_size: int = 25,
        start_index: int = 0,
        sort_by: str = "eventTime",
        sort_type: str = "desc",
        request_user: Optional[str] = None,
        repo_name: Optional[str] = None,
        resource_path: Optional[str] = None,
        action: Optional[str] = None,
        access_result: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        exclude_service_user: Optional[bool] = None,
        use_assets_endpoint: bool = False,
    ) -> Any:
        """Search Ranger data-access audit logs (allowed/denied resource access).

        access_result: 1=allowed, 0=denied (Ranger enum).
        start_date/end_date: MM/DD/YYYY (same format as Ranger UI).
        use_assets_endpoint: use /assets/accessAudit instead of /xaudit/access_audit.
        """
        return _redact(
            ranger.search_access_audits(
                page_size=page_size,
                start_index=start_index,
                sort_by=sort_by,
                sort_type=sort_type,
                request_user=request_user,
                repo_name=repo_name,
                resource_path=resource_path,
                action=action,
                access_result=access_result,
                start_date=start_date,
                end_date=end_date,
                exclude_service_user=exclude_service_user,
                use_assets_endpoint=use_assets_endpoint,
            )
        )

    @app.tool()
    async def count_access_audits(
        request_user: Optional[str] = None,
        repo_name: Optional[str] = None,
        resource_path: Optional[str] = None,
        action: Optional[str] = None,
        access_result: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        exclude_service_user: Optional[bool] = None,
    ) -> Any:
        """Count Ranger data-access audit records matching filters."""
        return _redact(
            ranger.count_access_audits(
                request_user=request_user,
                repo_name=repo_name,
                resource_path=resource_path,
                action=action,
                access_result=access_result,
                start_date=start_date,
                end_date=end_date,
                exclude_service_user=exclude_service_user,
            )
        )

    @app.tool()
    async def search_admin_audit_logs(
        page_size: int = 25,
        start_index: int = 0,
        sort_by: Optional[str] = None,
        sort_type: Optional[str] = None,
        object_name: Optional[str] = None,
        action: Optional[str] = None,
        updated_by: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> Any:
        """Search Ranger admin/transaction audit logs (policy and config changes).

        start_date/end_date: MM/DD/YYYY.
        """
        return _redact(
            ranger.search_admin_audit_logs(
                page_size=page_size,
                start_index=start_index,
                sort_by=sort_by,
                sort_type=sort_type,
                object_name=object_name,
                action=action,
                updated_by=updated_by,
                start_date=start_date,
                end_date=end_date,
            )
        )

    @app.tool()
    async def count_admin_audit_logs(
        object_name: Optional[str] = None,
        action: Optional[str] = None,
        updated_by: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> Any:
        """Count Ranger admin/transaction audit records matching filters."""
        return _redact(
            ranger.count_admin_audit_logs(
                object_name=object_name,
                action=action,
                updated_by=updated_by,
                start_date=start_date,
                end_date=end_date,
            )
        )

    @app.tool()
    async def get_admin_audit_log(log_id: int) -> Dict[str, Any]:
        """Get a single Ranger admin/transaction audit record by id."""
        return _redact(ranger.get_admin_audit_log(log_id))

    return app


async def _run_stdio() -> None:
    config = ServerConfig()
    ranger = build_client(config)
    server = create_server(ranger)
    await server.run_stdio_async()


def main() -> None:
    transport = os.getenv("MCP_TRANSPORT", "stdio").lower()
    if transport != "stdio":
        config = ServerConfig()
        ranger = build_client(config)
        server = create_server(ranger)
        server.run(transport=transport)
        return
    anyio.run(_run_stdio)


if __name__ == "__main__":
    main()
