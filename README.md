# EcomOps Log Analyzer

Read-only ecommerce log analyzer for Magento, PHP, Nginx, MySQL and cron logs.

See [the public architecture document](docs/ARCHITECTURE.md) for the
prompt-to-analysis flow and read-only security boundaries.

See [the MCP setup guide](docs/MCP.md) for connecting a local MCP client.

See [the AI host model](docs/AI.md) for the boundary between EcomOps and the
MCP client that interprets findings.

## Security and read-only guarantee

EcomOps is designed to read logs only. The MCP interface does not expose a
generic SSH command executor: it accepts a project, a configured log alias, a
time range, and output limits, then builds the allowed read-only operation
internally.

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
