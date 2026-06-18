# Ranger MCP Server

Model Context Protocol server for **Apache Ranger** on CDP — manage access policies, masking, tag-based policies, roles, users, and groups via agentic workflows.

## Features

- **Knox authentication** — JWT token, raw cookie, or Basic Auth (same pattern as Atlas MCP)
- **Policy lifecycle** — search, create, update, apply (upsert), delete
- **Access, masking & tag-based policies** — convenience builders plus raw JSON for full control
- **Identity management** — users, groups, roles and role membership
- **Tag metadata** — tag definitions, instances, tagged resources
- **Automatic retries** — exponential backoff on transient errors

### MCP Tools

**Services**
- `list_ranger_services`, `get_ranger_service`, `get_ranger_service_definition`

**Policies**
- `search_ranger_policies`, `get_ranger_policy`, `create_ranger_policy`, `update_ranger_policy`, `apply_ranger_policy`, `delete_ranger_policy`
- `create_access_policy` — resource-based access (Hive/HDFS/etc.)
- `create_masking_policy` — column masking
- `create_tag_based_policy` — tag-service policies (e.g. `cm_tag`)

**Roles**
- `list_ranger_roles`, `get_ranger_role`, `create_ranger_role`, `update_ranger_role`, `delete_ranger_role`
- `add_users_groups_to_role`, `get_roles_for_user`

**Users & groups**
- `list_ranger_users`, `get_ranger_user`, `create_ranger_user`, `update_ranger_user`, `delete_ranger_user`
- `list_ranger_groups`, `get_ranger_group`, `create_ranger_group`, `update_ranger_group`, `delete_ranger_group`
- `lookup_ranger_users`, `lookup_ranger_groups`

**Tags**
- `list_tag_definitions`, `get_tag_definition`, `list_tag_instances`, `list_tagged_resources`
- `search_tag_based_policies`

## Setup

### Local install

```bash
git clone <repo-url>
cd ranger-mcp-server
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

### Cursor / Claude Desktop MCP config

```json
{
  "mcpServers": {
    "ranger-mcp-server": {
      "command": "/FULL/PATH/TO/ranger-mcp-server/.venv/bin/python",
      "args": ["-m", "ranger_mcp_server.server"],
      "env": {
        "MCP_TRANSPORT": "stdio",
        "RANGER_GATEWAY_URL": "https://<host>/<topology>/cdp-proxy-api/ranger/service",
        "RANGER_USER": "<user>",
        "RANGER_PASS": "<password>"
      }
    }
  }
}
```

### uvx

```json
{
  "mcpServers": {
    "ranger-mcp-server": {
      "command": "uvx",
      "args": ["--from", "git+<repo-url>@main", "run-server"],
      "env": {
        "RANGER_GATEWAY_URL": "https://<host>/<topology>/cdp-proxy-api/ranger/service",
        "RANGER_USER": "<user>",
        "RANGER_PASS": "<password>"
      }
    }
  }
}
```

## Configuration

| Variable | Required | Description |
|----------|----------|-------------|
| `RANGER_GATEWAY_URL` | Yes | Full Knox Ranger API base (ends with `/ranger/service`) |
| `RANGER_USER` / `RANGER_PASS` | Yes* | Basic auth credentials |
| `KNOX_TOKEN` / `KNOX_COOKIE` | Alt | Knox JWT alternatives |
| `RANGER_VERIFY_SSL` | No | Default `true` |
| `HTTP_TIMEOUT_SECONDS` | No | Default `30` |

\* Or Knox token/cookie.

### CDP URL pattern

```
https://<cluster-host>/<topology>/cdp-proxy-api/ranger/service
```

Direct Ranger Admin (inside cluster): `https://<ranger-host>:6182/service`

## Example agent prompts

- "List all Ranger services"
- "Search Hive policies containing 'finance'"
- "Create a masking policy on column ssn in hr.employees"
- "Add group analysts to role finance_role"
- "Show tag-based policies for tag PII on cm_tag"

## License

Apache License 2.0
