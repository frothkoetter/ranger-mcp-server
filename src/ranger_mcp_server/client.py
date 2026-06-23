from __future__ import annotations

from typing import Any, Dict, List, Optional

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from .policy_helpers import normalize_audit_resource_path


class RangerError(Exception):
    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None):
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(message)

    def __str__(self) -> str:
        msg = super().__str__()
        if self.status_code:
            msg = f"[{self.status_code}] {msg}"
        if self.response_body:
            msg = f"{msg}\n\nRanger API Response:\n{self.response_body}"
        return msg


_RETRYABLE = (RangerError, requests.ConnectionError, requests.Timeout)

V2 = "public/v2/api"
TAGS = "tags"
XUSERS = "xusers"
XAUDIT = "xaudit"
ASSETS = "assets"


class RangerClient:
    def __init__(self, base_url: str, session: requests.Session, timeout_seconds: int = 30):
        self.base_url = base_url.rstrip("/")
        self.session = session
        self.timeout = timeout_seconds

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    @retry(
        retry=retry_if_exception_type(_RETRYABLE),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=5),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        resp = self.session.get(self._url(path), params=params, timeout=self.timeout)
        if not resp.ok:
            raise RangerError(f"GET {path} failed: {resp.reason}", resp.status_code, resp.text or "(empty)")
        return resp.json() if resp.content else {}

    @retry(
        retry=retry_if_exception_type(_RETRYABLE),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=5),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def _post(self, path: str, data: Any, params: Optional[Dict[str, Any]] = None) -> Any:
        resp = self.session.post(self._url(path), json=data, params=params, timeout=self.timeout)
        if not resp.ok:
            raise RangerError(f"POST {path} failed: {resp.reason}", resp.status_code, resp.text or "(empty)")
        return resp.json() if resp.content else {}

    @retry(
        retry=retry_if_exception_type(_RETRYABLE),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=5),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def _put(self, path: str, data: Any, params: Optional[Dict[str, Any]] = None) -> Any:
        resp = self.session.put(self._url(path), json=data, params=params, timeout=self.timeout)
        if not resp.ok:
            raise RangerError(f"PUT {path} failed: {resp.reason}", resp.status_code, resp.text or "(empty)")
        return resp.json() if resp.content else {}

    @retry(
        retry=retry_if_exception_type(_RETRYABLE),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=5),
        stop=stop_after_attempt(3),
        reraise=True,
    )
    def _delete(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        resp = self.session.delete(self._url(path), params=params, timeout=self.timeout)
        if not resp.ok:
            raise RangerError(f"DELETE {path} failed: {resp.reason}", resp.status_code, resp.text or "(empty)")
        return resp.json() if resp.content else {}

    def list_service_headers(self) -> Any:
        return self._get(f"{V2}/service-headers")

    def list_services(
        self,
        page_size: int = 25,
        start_index: int = 0,
        service_name: Optional[str] = None,
        service_type: Optional[str] = None,
        is_enabled: Optional[bool] = None,
    ) -> Any:
        params: Dict[str, Any] = {"pageSize": page_size, "startIndex": start_index}
        if service_name:
            params["serviceName"] = service_name
        if service_type:
            params["serviceType"] = service_type
        if is_enabled is not None:
            params["isEnabled"] = str(is_enabled).lower()
        return self._get(f"{V2}/service", params=params)

    def get_service_by_name(self, service_name: str) -> Dict[str, Any]:
        return self._get(f"{V2}/service/name/{service_name}")

    def get_service_def_by_name(self, service_type: str) -> Dict[str, Any]:
        return self._get(f"{V2}/servicedef/name/{service_type}")

    def search_policies(
        self,
        service_name: Optional[str] = None,
        policy_name: Optional[str] = None,
        policy_name_partial: Optional[str] = None,
        user: Optional[str] = None,
        group: Optional[str] = None,
        policy_type: Optional[int] = None,
        page_size: int = 25,
        start_index: int = 0,
    ) -> Any:
        params: Dict[str, Any] = {"pageSize": page_size, "startIndex": start_index}
        if policy_name:
            params["policyName"] = policy_name
        if policy_name_partial:
            params["policyNamePartial"] = policy_name_partial
        if user:
            params["user"] = user
        if group:
            params["group"] = group
        if policy_type is not None:
            params["policyType"] = policy_type
        if service_name:
            return self._get(f"{V2}/service/{service_name}/policy", params=params)
        return self._get(f"{V2}/policy", params=params)

    def get_policy(self, policy_id: int) -> Dict[str, Any]:
        return self._get(f"{V2}/policy/{policy_id}")

    def get_policy_by_name(self, service_name: str, policy_name: str) -> Dict[str, Any]:
        return self._get(f"{V2}/service/{service_name}/policy/{policy_name}")

    def create_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        return self._post(f"{V2}/policy", policy)

    def update_policy(self, policy_id: int, policy: Dict[str, Any]) -> Dict[str, Any]:
        return self._put(f"{V2}/policy/{policy_id}", policy)

    def apply_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        return self._post(f"{V2}/policy/apply", policy)

    def delete_policy_by_id(self, policy_id: int) -> Any:
        return self._delete(f"{V2}/policy/{policy_id}")

    def delete_policy_by_name(
        self,
        service_name: str,
        policy_name: str,
        zone_name: Optional[str] = None,
    ) -> Any:
        params: Dict[str, Any] = {"policyname": policy_name, "servicename": service_name}
        if zone_name:
            params["zoneName"] = zone_name
        return self._delete(f"{V2}/policy", params=params)

    def list_roles(self, page_size: int = 25, start_index: int = 0) -> Any:
        return self._get(f"{V2}/roles", params={"pageSize": page_size, "startIndex": start_index})

    def list_role_names(self) -> Any:
        return self._get(f"{V2}/roles/names")

    def get_role(self, role_id: int) -> Dict[str, Any]:
        return self._get(f"{V2}/roles/{role_id}")

    def get_role_by_name(self, role_name: str) -> Dict[str, Any]:
        return self._get(f"{V2}/roles/name/{role_name}")

    def create_role(
        self,
        role: Dict[str, Any],
        service_name: Optional[str] = None,
        create_non_exist_user_group: bool = False,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"createNonExistUserGroup": str(create_non_exist_user_group).lower()}
        if service_name:
            params["serviceName"] = service_name
        return self._post(f"{V2}/roles", role, params=params)

    def update_role(self, role_id: int, role: Dict[str, Any]) -> Dict[str, Any]:
        return self._put(f"{V2}/roles/{role_id}", role)

    def delete_role(self, role_id: int) -> Any:
        return self._delete(f"{V2}/roles/{role_id}")

    def add_users_and_groups_to_role(
        self,
        role_id: int,
        users: List[str],
        groups: List[str],
    ) -> Dict[str, Any]:
        payload = {
            "users": [{"name": name, "isAdmin": False} for name in users],
            "groups": [{"name": name, "isAdmin": False} for name in groups],
        }
        return self._put(f"{V2}/roles/{role_id}/addUsersAndGroups", payload)

    def get_roles_for_user(self, user_name: str) -> Any:
        return self._get(f"{V2}/roles/user/{user_name}")

    def list_users(self, page_size: int = 25, start_index: int = 0) -> Any:
        return self._get(f"{XUSERS}/users", params={"pageSize": page_size, "startIndex": start_index})

    def get_user_by_name(self, user_name: str) -> Dict[str, Any]:
        return self._get(f"{XUSERS}/users/userName/{user_name}")

    def create_user(self, user: Dict[str, Any]) -> Dict[str, Any]:
        return self._post(f"{XUSERS}/secure/users", user)

    def update_user(self, user_id: int, user: Dict[str, Any]) -> Dict[str, Any]:
        return self._put(f"{XUSERS}/secure/users/{user_id}", user)

    def delete_user(self, user_id: int) -> Any:
        return self._delete(f"{XUSERS}/secure/users/{user_id}")

    def list_groups(self, page_size: int = 25, start_index: int = 0) -> Any:
        return self._get(f"{XUSERS}/groups", params={"pageSize": page_size, "startIndex": start_index})

    def get_group_by_name(self, group_name: str) -> Dict[str, Any]:
        return self._get(f"{XUSERS}/groups/groupName/{group_name}")

    def create_group(self, group: Dict[str, Any]) -> Dict[str, Any]:
        return self._post(f"{XUSERS}/groups", group)

    def update_group(self, group_id: int, group: Dict[str, Any]) -> Dict[str, Any]:
        return self._put(f"{XUSERS}/groups/{group_id}", group)

    def delete_group(self, group_id: int) -> Any:
        return self._delete(f"{XUSERS}/groups/{group_id}")

    def lookup_users(self, name: str) -> Any:
        return self._get(f"{XUSERS}/lookup/users", params={"name": name})

    def lookup_groups(self, name: str) -> Any:
        return self._get(f"{XUSERS}/lookup/groups", params={"name": name})

    def list_tag_definitions(self) -> Any:
        return self._get(f"{TAGS}/tagdefs")

    def get_tag_definition_by_name(self, name: str) -> Dict[str, Any]:
        return self._get(f"{TAGS}/tagdef/name/{name}")

    def list_tags(self) -> Any:
        return self._get(f"{TAGS}/tags")

    def list_tagged_resources(self, service_name: Optional[str] = None) -> Any:
        if service_name:
            return self._get(f"{TAGS}/resources/service/{service_name}")
        return self._get(f"{TAGS}/resources")

    def search_tag_policies(
        self,
        tag_service_name: str,
        tag_name: Optional[str] = None,
        page_size: int = 25,
        start_index: int = 0,
    ) -> Any:
        params: Dict[str, Any] = {"pageSize": page_size, "startIndex": start_index}
        if tag_name:
            params["resource:tag"] = tag_name
        return self._get(f"{V2}/service/{tag_service_name}/policy", params=params)

    def _access_audit_params(
        self,
        *,
        page_size: Optional[int] = None,
        start_index: Optional[int] = None,
        sort_by: Optional[str] = None,
        sort_type: Optional[str] = None,
        request_user: Optional[str] = None,
        repo_name: Optional[str] = None,
        resource_path: Optional[str] = None,
        action: Optional[str] = None,
        access_result: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        exclude_service_user: Optional[bool] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = page_size
        if start_index is not None:
            params["startIndex"] = start_index
        if sort_by:
            params["sortBy"] = sort_by
        if sort_type:
            params["sortType"] = sort_type
        if request_user:
            params["requestUser"] = request_user
        if repo_name:
            params["repoName"] = repo_name
        if resource_path:
            params["resourcePath"] = normalize_audit_resource_path(resource_path)
        if action:
            params["action"] = action
        if access_result is not None:
            params["accessResult"] = access_result
        if start_date:
            params["startDate"] = start_date
        if end_date:
            params["endDate"] = end_date
        if exclude_service_user is not None:
            params["excludeServiceUser"] = str(exclude_service_user).lower()
        return params

    def search_access_audits(
        self,
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
        use_assets_endpoint: bool = True,
    ) -> Any:
        params = self._access_audit_params(
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
        )
        path = f"{ASSETS}/accessAudit" if use_assets_endpoint else f"{XAUDIT}/access_audit"
        return self._get(path, params=params)

    def count_access_audits(
        self,
        request_user: Optional[str] = None,
        repo_name: Optional[str] = None,
        resource_path: Optional[str] = None,
        action: Optional[str] = None,
        access_result: Optional[int] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        exclude_service_user: Optional[bool] = None,
        use_assets_endpoint: bool = True,
    ) -> Any:
        if use_assets_endpoint:
            result = self.search_access_audits(
                page_size=1,
                start_index=0,
                request_user=request_user,
                repo_name=repo_name,
                resource_path=resource_path,
                action=action,
                access_result=access_result,
                start_date=start_date,
                end_date=end_date,
                exclude_service_user=exclude_service_user,
                use_assets_endpoint=True,
            )
            return {"value": result.get("totalCount", 0)}
        params = self._access_audit_params(
            request_user=request_user,
            repo_name=repo_name,
            resource_path=resource_path,
            action=action,
            access_result=access_result,
            start_date=start_date,
            end_date=end_date,
            exclude_service_user=exclude_service_user,
        )
        return self._get(f"{XAUDIT}/access_audit/count", params=params)

    def _admin_audit_params(
        self,
        *,
        page_size: Optional[int] = None,
        start_index: Optional[int] = None,
        sort_by: Optional[str] = None,
        sort_type: Optional[str] = None,
        object_name: Optional[str] = None,
        action: Optional[str] = None,
        updated_by: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if page_size is not None:
            params["pageSize"] = page_size
        if start_index is not None:
            params["startIndex"] = start_index
        if sort_by:
            params["sortBy"] = sort_by
        if sort_type:
            params["sortType"] = sort_type
        if object_name:
            params["objectName"] = object_name
        if action:
            params["action"] = action
        if updated_by:
            params["updatedBy"] = updated_by
        if start_date:
            params["startDate"] = start_date
        if end_date:
            params["endDate"] = end_date
        return params

    def search_admin_audit_logs(
        self,
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
        params = self._admin_audit_params(
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
        return self._get(f"{XAUDIT}/trx_log", params=params)

    def count_admin_audit_logs(
        self,
        object_name: Optional[str] = None,
        action: Optional[str] = None,
        updated_by: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
    ) -> Any:
        params = self._admin_audit_params(
            object_name=object_name,
            action=action,
            updated_by=updated_by,
            start_date=start_date,
            end_date=end_date,
        )
        return self._get(f"{XAUDIT}/trx_log/count", params=params)

    def get_admin_audit_log(self, log_id: int) -> Dict[str, Any]:
        return self._get(f"{XAUDIT}/trx_log/{log_id}")
