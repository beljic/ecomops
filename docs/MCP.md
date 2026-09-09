# MCP setup

EcomOps exposes one typed MCP tool over stdio:

```text
analyze_project_log(project, log_alias, since, until, max_lines, max_bytes)
```

The tool resolves `project` and `log_alias` from the configured project
registry. It does not accept a shell command, arbitrary remote path, script,
upload target, or password.

## Start the server

After installing the package with `uv`, configure the MCP client to launch:

```json
{
  "mcpServers": {
    "ecomops": {
      "command": "uv",
      "args": [
        "run",
        "--project",
        "/path/to/ecomops",
        "ecomops-mcp"
      ],
      "env": {
        "ECOMOPS_PROJECTS_DIR": "/Users/example/.config/ecomops/projects"
      }
    }
  }
}
```

The example path is synthetic. Use a directory outside the repository for
private project configuration.

## Project configuration

Example local project:

```yaml
name: example-shop
platform: magento
connection:
  type: local
  root: /srv/example-shop
log_aliases:
  php:
    path: var/log/php.log
    type: php
```

Example SSH project:

```yaml
name: example-remote
connection:
  type: ssh
  host: logs.example.test
  user: log-reader
  root: /srv/example-remote/current
  key_path: ~/.ssh/ecomops_readonly
  known_hosts_path: ~/.ssh/known_hosts
log_aliases:
  access:
    path: ../logs/example-remote/access.log
    type: nginx
```

SSH passwords are not stored in project configuration. The SSH account should
be dedicated to read-only log access and host-key verification must remain
enabled.

For a direct CLI run, password authentication can be requested explicitly:

```bash
uv run ecomops project example-remote analyze access --prompt-password
```

The password is read without echo, kept only in memory for that one SSH
connection, and never written to YAML, environment files, logs, or temporary
files. The MCP server does not accept passwords as tool arguments; configure
its SSH projects with a key or SSH agent instead.

## Security boundary

The server performs bounded reads only. It never creates temporary files,
writes to remote systems, uses write-capable SFTP operations, invokes `sudo`,
or performs remediation. Unknown tool arguments are rejected. See
[the architecture and security boundary](ARCHITECTURE.md) for the diagrams
and the full guarantee.
