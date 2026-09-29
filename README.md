# EcomOps Log Analyzer

Read-only ecommerce log analyzer for Magento, PHP, Nginx, MySQL and cron logs.

See [the public architecture document](docs/ARCHITECTURE.md) for the
prompt-to-analysis flow and read-only security boundaries.

See [the MCP setup guide](docs/MCP.md) for connecting a local MCP client.

See [the AI host model](docs/AI.md) for the boundary between EcomOps and the
MCP client that interprets findings.

## Install the MCP server

EcomOps is currently installed from source:

```bash
git clone https://github.com/beljic/ecomops.git
cd ecomops
uv sync
```

Configure your MCP client to start the server from the checkout:

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
        "ECOMOPS_PROJECTS_DIR": "/path/to/private/ecomops-projects"
      }
    }
  }
}
```

Replace only the example paths. Keep project YAML files and SSH key paths
outside this public repository. Full project configuration and security
guidance is in [the MCP setup guide](docs/MCP.md).

For remote projects, EcomOps uses an SSH key or SSH agent first. If SSH denies
access, the CLI can take a password with `--prompt-password` or
`--password-stdin`, and an MCP client that supports elicitation is asked once
for a username and password for that single request. Passwords are never
stored or passed as tool arguments; see
[SSH authentication: MCP vs CLI](docs/MCP.md#ssh-authentication-mcp-vs-cli).

What EcomOps can do:

- analyze PHP, Magento, Nginx, MySQL / MariaDB, cron, and generic logs with
  deterministic analyzers; the parser recognizes the bracketed
  `[timestamp] LEVEL: message` format and the Nginx error-log and `combined`
  access formats;
- explain every read: file state, sampled window, recognized and filtered
  lines, and a warning instead of a misleading "No findings";
- follow rotated logs through glob aliases such as `transfer-*.log`;
- check every alias of a project without analyzing it
  (`ecomops project <name> check`);
- summarize web traffic and scan for security indicators (scanner probes,
  login guessing, locally configured Tor ranges);
- accept time ranges such as `30m`, `24h`, `7d`, `2w`, `1mo`, or ISO dates
  ([details](docs/MCP.md#time-ranges)).

## Security and read-only guarantee

EcomOps is designed to read log files only. The MCP interface does not expose
a generic SSH command executor: it accepts a project, a configured log alias, a
time range, and output limits, then builds the allowed read-only operation
internally. Over SSH it runs only a bounded `tail` of one log file and a
`find` that checks one log file or lists one log folder without following
symlinks.

Every alias must name a log file inside an allowed log folder. System folders
(`/etc`, `/proc`, `/root`, ...), secret folders (`.ssh`, ...), Magento
`app/etc`, and configuration or secret files (`.env`, `.php`, `.key`, ...) are
always refused; see [the log path policy](docs/MCP.md#log-path-policy).

The MCP server must never create, modify, delete, move, upload, or truncate
files on a remote server. It must not use `sudo`, arbitrary scripts, shell
redirections, write-capable SFTP operations, or remote remediation commands.
Log data is streamed with bounded limits; temporary files and generated remote
files are not required.

This guarantee applies to the standard, unmodified EcomOps package. Users must
only install the package from a trusted source and should configure a
dedicated SSH account/key with read-only permissions and host-key verification.
A user who installs modified or malicious code, or grants write permissions to
the SSH account, is outside this guarantee.

EcomOps does not bootstrap SSH access. Never use `ssh-copy-id`, modify remote
`authorized_keys`, or run remote setup commands for an EcomOps project. The
configured key must already be authorized, and the remote account should
already have the intended read-only permissions.

All project names, domains, paths, and credentials shown in this repository are
synthetic examples. Real customer or company details must never be committed.

## Development

```bash
uv run ecomops --help
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src
```
