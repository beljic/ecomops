# MCP setup

> **Authentication rule:** remote projects use an SSH key or SSH agent first.
> If SSH denies access, an MCP client that supports elicitation is asked once
> for a username and password for that single request; see
> [SSH authentication: MCP vs CLI](#ssh-authentication-mcp-vs-cli). Passwords
> are never tool arguments and are never stored.

EcomOps exposes five typed MCP tools over stdio. Every tool takes a configured
project name and, where relevant, a configured log alias. None of them accepts
a shell command, raw path, glob, script, upload target, or password.

| Tool | Arguments | What it returns |
|---|---|---|
| `analyze_project_log` | `project, log_alias, since, until, max_lines, max_bytes` | Findings from the deterministic analyzers plus read metadata |
| `check_project` | `project` | Per-alias file health and parser recognition; no analyzers run |
| `list_log_files` | `project, log_alias` | Newest-first files matched by a glob alias (at most 50) |
| `traffic_summary` | `project, log_alias, since, until, max_lines, max_bytes, top_n` | Top client IPs, status counts, paths, user agents, busiest minutes |
| `security_scan` | `project, log_alias, since, until, max_lines, max_bytes` | Scanner probes, login guessing, malformed requests, local Tor matches |

Unknown arguments are rejected before any file is touched. `top_n` is 1-50
(default 10).

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

After installing the MCP server, the project registry is initially empty.
Create the directory configured by `ECOMOPS_PROJECTS_DIR` and add one YAML
file per project. A successful `claude mcp get ecomops` only confirms that the
MCP process starts; it does not confirm that a project YAML file or SSH
credentials are configured.

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
log_dirs:
  - ../logs/example-remote
  - var/log
log_aliases:
  access:
    path: ../logs/example-remote/access.log
    type: nginx
```

### Log path policy

EcomOps reads log files only. Every alias is checked when the project is
loaded, and a project that breaks a rule is rejected:

- The file must be inside an allowed log folder. By default, the allowed
  folders are the connection `root` and `/var/log`. `log_dirs` replaces those
  defaults with an explicit list; relative entries are resolved against `root`.
- The file name must look like a log: `*.log`, `*.log.1`, `*.log-20260901`, or
  a glob such as `transfer-*.log`. Log names without an extension (`syslog`,
  `messages`, `cron`) are accepted only inside `/var/log`.
- These are always refused, even when listed in `log_dirs`:
  - system folders: `/etc`, `/proc`, `/sys`, `/dev`, `/boot`, `/root`, `/run`;
  - secret folders: `.ssh`, `.gnupg`, `.aws`, `.git`, `.kube`, `.docker`;
  - Magento `app/etc`;
  - configuration and secret files: `.env`, `.php`, `.ini`, `.conf`, `.xml`,
    `.json`, `.yaml`, `.sql`, `.pem`, `.key`.
- Locally, the real path (after resolving every symlink) is checked again
  before reading. Over SSH, the file and every folder between it and its
  allowed log folder are checked before each read and listing; if any of
  them is a symlink, or the file is not a regular file, nothing is read.
- `ecomops analyze <file>` (a local file named on the command line) applies
  the same name rule and deny list to the file's real path.

### Log aliases

Each alias has a `path` and a `type`. Supported types are `php`, `magento`,
`nginx`, `mysql`, `mariadb`, `cron`, and `generic`; any other value is
rejected. The parser recognizes the bracketed `[timestamp] LEVEL: message`
format, the nginx error-log format (`2026/09/03 12:00:00 [error] 1#1: ...`),
and the nginx `combined` access format (optionally followed by a quoted
`$http_x_forwarded_for` field). Lines in any other format are still passed to
the analyzers and are counted as unrecognized in the report.

Nginx aliases can choose where the client IP comes from:

```yaml
log_aliases:
  transfer:
    path: var/log/nginx/transfer-*.log
    type: nginx
    client_ip_source: x_forwarded_for   # default: socket
```

- `socket` (default): the connecting address (`$remote_addr`).
- `x_forwarded_for`: the first valid IP address in the forwarded-for field,
  falling back to the socket address when the field is missing or invalid.
  Use this only when every request passes through a proxy or CDN you control;
  otherwise clients can spoof the header. The policy is set per alias so a
  proxy or CDN migration is an explicit configuration change.

SSH passwords are not stored in project configuration. The SSH account should
be dedicated to read-only log access and host-key verification must remain
enabled.

For MCP access, fill in all of these SSH fields:

- `host`: DNS name or IP address;
- `user`: SSH username;
- `key_path`: private key readable by the local MCP process;
- `known_hosts_path`: local known-hosts file used for host-key verification;
- `root`: optional remote root for resolving relative log paths.

The `key_path` is required unless the MCP process can use an SSH agent or a
default SSH key. Do not add `password` to the YAML file; it is rejected by the
configuration schema.

The key must already be authorized on the remote server. EcomOps never
installs keys or changes SSH access. Do **not** run `ssh-copy-id`, edit
`~/.ssh/authorized_keys`, use `ssh`, `sudo`, or any other remote setup command
as part of EcomOps configuration. Those are administrative changes outside the
read-only analyzer boundary.

## SSH authentication: MCP vs CLI

EcomOps always tries the configured SSH key or SSH agent first.

**CLI.** Password authentication must be requested explicitly:

```bash
uv run ecomops project example-remote analyze access --prompt-password
```

For non-interactive runs, pipe the password on stdin instead. Exactly one
trailing newline is removed; any other whitespace is kept as part of the
password. `--password-stdin` and `--prompt-password` cannot be combined.

```bash
secret-tool lookup service example-remote | \
  uv run ecomops project example-remote analyze access --password-stdin
```

**MCP.** Tool arguments never contain a username or password. When SSH denies
the key or agent, the server asks the MCP client once, through elicitation, for
a username and password for this one request, then retries exactly once:

- the client declines or cancels: the tool fails with "no credentials were
  provided";
- the client does not support elicitation: the tool fails and asks you to
  configure an SSH key or agent;
- the retry is also denied: the tool fails with "denied for the provided
  credentials" and does not ask again.

On MCP protocol 2026-07-28 and later, the question is returned as an
`input_required` result and the answer arrives on the client's retried call.
Older clients are asked in-band. In both cases, the password is kept only in
memory for that one call, is never echoed in results, errors, or logs, and is
never written to YAML, environment files, reports, caches, or temporary files.

## Time ranges

`since` and `until` (CLI `--since` / `--until`) accept:

- `all` (default): read the beginning of the file up to the byte/line limits;
- a positive relative amount with a unit: `m` (minutes), `h` (hours),
  `d` (days), `w` (weeks), or `mo` (calendar months), for example `30m`,
  `24h`, `7d`, `2w`, `1mo`;
- an ISO date or timestamp, for example `2026-09-01` (midnight UTC) or
  `2026-09-01T00:00:00Z`.

Zero, negative, fractional, and unknown values are rejected with an
`Invalid time range` error. Relative and ISO ranges read the end of the file,
so older entries outside the byte limit are not seen; reports mark such reads
as bounded.

## Project check and file discovery

`check_project` (CLI: `ecomops project <name> check`, with `--format
terminal|json|markdown`) inspects every alias without running analyzers. For
each alias it reports the resolved file (for a glob alias: the candidates,
newest first, and the selected file), whether the file exists and is readable,
its size and modification time, a bounded sample (up to 64 KB and 1,000 lines),
how many sample lines the parser recognized, and any warning. SSH errors on one
alias are reported for that alias; an authentication denial stops the whole
check so credentials are requested only once.

A glob alias such as `var/log/nginx/transfer-*.log` may use `*` and `?` in the
file name only. It lists one folder (no recursion, regular files only, at most
1,000 matches) and analyzes the newest match.

## Structured output

`analyze_project_log` keeps its original `metadata` fields and, when a file was
read, adds:

- `source`: `exists` (`null` when it cannot be determined, for example when a
  folder above the file is not accessible), `readable`, `size_bytes`,
  `modified_at`, `error` (such as `file not found`, `permission denied: the
  file or a folder above it is not accessible`, or `permission denied reading
  the file`);
- `sampling`: `direction` (`head` for `all`, `tail` for time ranges),
  `max_bytes`, `max_lines`, `sampled_bytes`, `complete_lines`,
  `sampled_range`;
- `parse_stats`: `total_lines`, `parsed_lines`, `unparsed_lines`,
  `level_counts`, `format_counts`, `filtered_out_lines`;
- `actual_range`: the time range of the analyzed entries;
- `warnings`: why "No findings" may not mean "no problems", for example
  `log file is empty`, `source unavailable: file not found`,
  `parser recognized none of N sampled lines`, or
  `all N sampled lines were outside the time range`.

`traffic_summary` and `security_scan` return `read` (the same read metadata,
plus `project`, `alias`, `path`, `connection_type`) and `summary` or `scan`.
`summary.status_by_ip` lists up to `top_n` client IPs that received 4xx or 5xx
responses, most errors first, each with its own status counts (for example
`{"403": 1, "404": 1, "429": 1}`).
Counts are top-N lists sorted by count, then value. Paths drop their query
string in traffic counts; samples are redacted and cut to 200 characters. No
raw log lines are returned.

Tor classification uses only CIDRs listed in the project file; no external
threat-intelligence service is called. Without a list, the result says
`"status": "unavailable"`:

```yaml
security:
  tor_cidrs:
    - 198.51.100.0/24
  login_threshold: 5   # login POSTs per client IP before it is reported
```

## Security boundary

The server performs bounded reads of log files only. Over SSH it can run
only `tail` and `find`, in these three fixed forms, always built internally
from a configured, policy-checked path:

- `tail -c <max_bytes> -- <log file>`: read the end of one log file;
- `find <absolute paths> -maxdepth 0 -printf '%y %s %T@\n'`: report the type,
  size, and modification time of one log file and the folders above it (up to
  its allowed log folder), without following symlinks;
- `find <absolute folder> -maxdepth 1 -type f -name <pattern> -printf ...`:
  list the regular files of one log folder for a glob alias.

It never creates temporary files, writes to remote systems, opens SFTP,
requests a TTY or forwarding, invokes `sudo`, or performs remediation. It
never bootstraps access: no `ssh-copy-id`, no `authorized_keys` edits, no
remote setup commands, and no arbitrary commands. Unknown tool arguments are
rejected. See [the architecture and security boundary](ARCHITECTURE.md) for
the diagrams and the full guarantee.
