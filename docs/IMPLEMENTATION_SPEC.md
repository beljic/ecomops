# EcomOps Log Analyzer - Python Implementation Specification

This document is the implementation brief for building **EcomOps Log Analyzer**, an open-source read-only terminal-first Python CLI for ecommerce log analysis, remote log fetching, and optional AI-assisted diagnostics.

The goal is to give a coding agent enough detail to implement the project incrementally without inventing unnecessary architecture.

## 1. Product Goal

EcomOps Log Analyzer helps ecommerce developers, Magento agencies, and DevOps engineers analyze logs from:

- Magento
- Shopify integrations
- PHP applications
- Nginx
- Apache
- MySQL / MariaDB
- cron jobs
- custom import/export processes

The tool must work without paid AI APIs. Regex and heuristic analyzers are the core product. AI providers are optional enrichers.

The CLI should answer:

- What went wrong?
- How often did it happen?
- Where is the evidence?
- How severe is it?
- What should I check next?

## 2. Technical Stack

Use:

- Python 3.12+
- Typer for CLI
- Rich for terminal output
- Pydantic v2 for config and domain models
- python-dotenv for `.env` loading
- PyYAML or ruamel.yaml for YAML config
- Paramiko for MVP SSH support
- pytest
- ruff
- mypy
- uv

Avoid:

- Web UI
- SaaS backend
- long-running daemon
- database in MVP
- automatic remote remediation
- mandatory AI dependency

## 3. Architecture

Use a layered modular architecture:

```text
CLI Layer
  Typer commands, command options, terminal UX

Application Layer
  Orchestrates config, projects, log sources, analyzer pipeline, reports, AI enrichment

Domain Layer
  Typed models, enums, exceptions, shared result objects

Infrastructure Layer
  Local file reading, SSH fetching, config loading, cache, AI clients

Plugin Layer
  Optional analyzers and AI providers through Python entry points
```

Core processing flow:

```text
resolve input source
  -> read local file or fetch remote log
  -> parse/split log entries
  -> run analyzers
  -> aggregate repeated findings
  -> optionally enrich with AI
  -> render terminal/json/markdown report
```

## 4. Target Directory Structure

Create this structure:

```text
ecomops-assistant/
  pyproject.toml
  README.md
  LICENSE
  .env.example

  src/
    ecomops/
      __init__.py
      __main__.py

      cli/
        __init__.py
        app.py
        commands/
          __init__.py
          analyze.py
          project.py
          config.py
          ai.py

      core/
        __init__.py
        enums.py
        exceptions.py
        models.py

      config/
        __init__.py
        env.py
        loader.py
        paths.py
        schema.py

      projects/
        __init__.py
        registry.py
        resolver.py
        schema.py

      logs/
        __init__.py
        filters.py
        parsers.py
        readers.py
        sources.py

      ssh/
        __init__.py
        client.py
        fetcher.py
        profiles.py

      analyzers/
        __init__.py
        base.py
        pipeline.py
        registry.py
        rules/
          __init__.py
          php.py
          magento.py
          nginx.py
          mysql.py
          cron.py
          api.py
          payment.py
          security.py

      ai/
        __init__.py
        base.py
        enrichment.py
        prompts.py
        providers/
          __init__.py
          noop.py
          openai.py
          anthropic.py
          ollama.py

      reports/
        __init__.py
        json.py
        markdown.py
        terminal.py

      cache/
        __init__.py
        keys.py
        store.py

      plugins/
        __init__.py
        loader.py

  tests/
    unit/
    integration/
    fixtures/
      logs/
        magento_exception.log
        nginx_error.log
        mysql_error.log
        cron_failure.log
```

## 5. Domain Models

Implement domain models in `src/ecomops/core/models.py`.

Use Pydantic models.

Required models:

```python
from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class LogSource(BaseModel):
    type: Literal["local", "ssh", "stdin"]
    path: str | None = None
    project: str | None = None
    alias: str | None = None


class LogEntry(BaseModel):
    timestamp: datetime | None = None
    level: str | None = None
    source: str
    message: str
    raw: str
    line_number: int | None = None


class Evidence(BaseModel):
    message: str
    source: str
    sample: str
    line_number: int | None = None


class Finding(BaseModel):
    id: str
    title: str
    severity: Severity
    category: str
    root_cause_guess: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    count: int = 1
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    recommended_steps: list[str] = Field(default_factory=list)


class AnalysisContext(BaseModel):
    source: LogSource
    project_name: str | None = None
    platform: str | None = None
    since: str | None = None
    analyzers: list[str] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    source: LogSource
    findings: list[Finding]
    generated_at: datetime
    summary: str | None = None
    ai_enriched: bool = False
```

## 6. Configuration Models

Implement in `src/ecomops/config/schema.py`.

```python
from pydantic import BaseModel, Field


class SSHProfileConfig(BaseModel):
    host: str
    user: str
    port: int = 22
    key_path: str | None = None
    timeout_seconds: int = 10
    known_hosts: str | None = None


class ProjectConfig(BaseModel):
    name: str
    platform: str = "custom"
    root: str | None = None
    ssh_profile: str | None = None
    log_aliases: dict[str, str] = Field(default_factory=dict)
    default_analyzers: list[str] = Field(default_factory=list)


class DefaultsConfig(BaseModel):
    ai_provider: str = "noop"
    report_format: str = "terminal"
    cache_ttl_minutes: int = 60
    max_log_bytes: int = 10_485_760


class AppConfig(BaseModel):
    defaults: DefaultsConfig = Field(default_factory=DefaultsConfig)
    ssh_profiles: dict[str, SSHProfileConfig] = Field(default_factory=dict)
    projects: dict[str, ProjectConfig] = Field(default_factory=dict)
```

Configuration precedence:

```text
CLI options
  -> environment variables
  -> YAML config
  -> built-in defaults
```

Default config path:

```text
~/.config/ecomops/config.yaml
```

Default cache path:

```text
~/.cache/ecomops
```

Environment variables:

```env
ECOMOPS_CONFIG=~/.config/ecomops/config.yaml
ECOMOPS_CACHE_DIR=~/.cache/ecomops
ECOMOPS_AI_PROVIDER=noop

OPENAI_API_KEY=
ANTHROPIC_API_KEY=
OLLAMA_BASE_URL=http://localhost:11434
```

Example YAML:

```yaml
defaults:
  ai_provider: noop
  report_format: terminal
  cache_ttl_minutes: 60
  max_log_bytes: 10485760

ssh_profiles:
  noir_prod:
    host: example.com
    user: deploy
    port: 22
    key_path: ~/.ssh/id_ed25519
    known_hosts: ~/.ssh/known_hosts

projects:
  noir:
    name: noir
    platform: magento
    root: /var/www/noir/current
    ssh_profile: noir_prod
    log_aliases:
      exception: var/log/exception.log
      system: var/log/system.log
      cron: var/log/cron.log
      nginx-error: /var/log/nginx/noir-error.log
      mysql: /var/log/mysql/error.log
    default_analyzers:
      - magento
      - php
      - nginx
      - mysql
      - cron
```

## 7. CLI Design

Use Typer.

Entrypoint:

```bash
ecomops
```

Required commands for MVP:

```bash
ecomops analyze <path>
ecomops analyze <path> --since 24h
ecomops analyze <path> --format terminal
ecomops analyze <path> --format json
ecomops analyze <path> --format markdown
ecomops analyze <path> --ai

ecomops project list
ecomops project show <name>
ecomops project <name> analyze <alias-or-path>
ecomops project <name> analyze <alias-or-path> --remote

ecomops config init
ecomops config show
ecomops config validate

ecomops ai providers
ecomops ai test
```

Commands that may come after MVP:

```bash
ecomops project <name> ssh fetch <alias>
ecomops project <name> logs analyze --remote nginx-error,mysql --since 24h
```

CLI implementation rules:

- CLI modules should be thin.
- Do not put analyzer logic inside command handlers.
- Command handlers should call services/pipeline functions.
- All errors should be caught at CLI boundary and rendered as readable Rich messages.

## 8. Local Log Reading

Implement local file reading in `logs/readers.py`.

Requirements:

- Accept plain text files.
- Enforce max byte limit from config unless user overrides.
- Preserve line numbers.
- Support UTF-8 with graceful replacement for invalid characters.
- Return raw lines or `LogEntry` objects.

MVP parser can be simple:

- Try to detect timestamp with common regex patterns.
- Try to detect log level.
- Preserve raw line.
- Multi-line stack traces may initially be grouped by simple continuation rules.

Common timestamp examples:

```text
[2026-05-25T12:00:00.000000+00:00]
2026-05-25 12:00:00
25/May/2026:12:00:00 +0000
```

## 9. SSH Fetching

Use Paramiko for MVP.

Implement in:

- `ssh/client.py`
- `ssh/fetcher.py`

Requirements:

- Read only.
- Use configured SSH profile.
- Support key-based auth.
- Respect timeout.
- Do not enable remote writes.
- Do not use sudo by default.
- Use conservative commands only.

Initial remote command:

```bash
tail -n <lines> <escaped_path>
```

Default line count:

```text
5000
```

Important:

- Escape remote paths safely.
- Prefer `shlex.quote`.
- Surface permission errors clearly.
- Store fetched logs in cache with project/source/timestamp.

## 10. Analyzer Interface

Implement in `analyzers/base.py`.

```python
from typing import Protocol

from ecomops.core.models import AnalysisContext, Finding, LogEntry


class Analyzer(Protocol):
    id: str
    name: str
    categories: set[str]

    def supports(self, context: AnalysisContext) -> bool:
        ...

    def analyze(
        self,
        entries: list[LogEntry],
        context: AnalysisContext,
    ) -> list[Finding]:
        ...
```

Analyzer rules:

- An analyzer must never raise for normal malformed log lines.
- Analyzer errors should be isolated by the pipeline.
- Each finding must include evidence.
- Findings should be deterministic.
- Findings should avoid duplicated noise by grouping repeated patterns.

## 11. Built-In Analyzers

### PHP Analyzer

Detect:

- `PHP Fatal error`
- `Allowed memory size ... exhausted`
- `Maximum execution time ... exceeded`
- `Uncaught Error`
- `Class ... not found`
- `Call to undefined method`
- `Permission denied`

Suggested severity:

- memory exhausted: high
- fatal error: high
- undefined class/method: high or medium
- permission denied: medium/high depending on count

### Magento Analyzer

Detect:

- `report.CRITICAL`
- `main.CRITICAL`
- indexing failures
- generated class/interceptor issues
- `No such entity`
- missing table/column
- Elasticsearch/OpenSearch connection errors
- cache backend errors
- deployment mode/static content issues

Suggested categories:

- `magento`
- `indexing`
- `catalog`
- `search`
- `cache`

### Nginx Analyzer

Detect:

- `upstream timed out`
- `connect() failed`
- `recv() failed`
- `502`
- `503`
- `504`
- suspicious high request count by IP in access logs
- bot/user-agent bursts

### MySQL Analyzer

Detect:

- `Deadlock found`
- `Lock wait timeout exceeded`
- `Too many connections`
- `Lost connection to MySQL server`
- `Table ... is marked as crashed`
- disk full messages

### Cron Analyzer

Detect:

- failed cron jobs
- missed schedule messages
- overlapping jobs
- import/export job failures
- Magento cron group failures

### API / Payment Analyzer

Detect:

- webhook signature failures
- HTTP 401/403 from APIs
- HTTP 429 rate limit
- gateway timeout
- payment declined
- payment authorization/capture failures

## 12. Analyzer Pipeline

Implement in `analyzers/pipeline.py`.

Responsibilities:

1. Select analyzers by CLI options, project defaults, or source detection.
2. Run analyzers.
3. Catch and record analyzer errors without stopping the full analysis.
4. Aggregate duplicate findings.
5. Sort by severity and count.
6. Return `AnalysisReport`.

Severity ordering:

```text
critical > high > medium > low > info
```

Aggregation strategy:

- Group by `finding.id`.
- Merge evidence samples up to a configured limit.
- Sum counts.
- Preserve first_seen and last_seen when available.

## 13. AI Provider Abstraction

AI is optional.

Default provider:

```text
noop
```

Implement in `ai/base.py`:

```python
from typing import Protocol

from ecomops.core.models import AnalysisContext, Finding


class AIProvider(Protocol):
    id: str

    def is_available(self) -> bool:
        ...

    def enrich_findings(
        self,
        findings: list[Finding],
        context: AnalysisContext,
    ) -> list[Finding]:
        ...
```

Providers:

- `noop`: returns findings unchanged
- `ollama`: local HTTP API
- `openai`: optional dependency or lazy import
- `anthropic`: optional dependency or lazy import

AI safety rules:

- Do not send full raw logs by default.
- Send only structured findings and limited evidence samples.
- Redact secrets before AI enrichment.
- AI must not create fake evidence.
- If AI fails, return heuristic report and show warning.

## 14. Redaction

Implement redaction before terminal output and AI enrichment.

Redact:

- bearer tokens
- API keys
- cookies
- session IDs
- emails
- credit card-like numbers
- Magento admin URLs with secret keys
- authorization headers

Create `security.py` or `logs/filters.py` helper:

```python
def redact_sensitive_text(text: str) -> str:
    ...
```

## 15. Report Rendering

Implement renderers:

- `reports/terminal.py`
- `reports/json.py`
- `reports/markdown.py`

Terminal report with Rich should show:

```text
EcomOps Analysis Report
Source: var/log/exception.log
Generated: 2026-05-25 12:30:00

Summary:
  3 high, 2 medium, 4 low findings

[HIGH] PHP memory exhausted
Category: php
Count: 42
Root cause guess: A command or request exceeded configured PHP memory_limit.
Evidence:
  var/log/exception.log:151 Allowed memory size of ...
Recommended next steps:
  1. Identify recurring command/request.
  2. Check memory_limit and recent code changes.
  3. Review imports, collections, and custom observers.
```

JSON renderer:

- Serialize `AnalysisReport`.
- Suitable for automation.

Markdown renderer:

- Suitable for incident notes or GitHub issues.

## 16. Plugin Architecture

MVP should support analyzer plugins only.

Use Python entry points:

```toml
[project.entry-points."ecomops.analyzers"]
custom_imports = "my_plugin.analyzers:CustomImportAnalyzer"
```

Plugin loader:

- Load entry points from `ecomops.analyzers`.
- Instantiate analyzers.
- Ignore broken plugins with warning unless strict mode is enabled.

Do not build a plugin marketplace in MVP.

## 17. Cache Strategy

Use JSON files under:

```text
~/.cache/ecomops
```

Suggested structure:

```text
~/.cache/ecomops/
  fetched/
  reports/
  ai/
```

MVP cache:

- Store fetched remote logs.
- Store optional AI enrichment by hash.

Do not use SQLite in MVP.

Cache key should include:

- project name
- source path
- source type
- file size or fetch timestamp
- analyzer version
- AI provider/model if AI is used

## 18. Error Handling

Implement exceptions in `core/exceptions.py`:

```python
class EcomOpsError(Exception): ...
class ConfigError(EcomOpsError): ...
class ProjectNotFoundError(EcomOpsError): ...
class LogSourceError(EcomOpsError): ...
class SSHConnectionError(EcomOpsError): ...
class AnalyzerError(EcomOpsError): ...
class AIProviderError(EcomOpsError): ...
class ReportRenderError(EcomOpsError): ...
```

CLI should render friendly messages:

```text
Could not read log alias "nginx-error" for project "noir".
Profile: noir_prod
Path: /var/log/nginx/noir-error.log
Reason: permission denied

Try:
  - verify the SSH user can read the file
  - check log_aliases in ~/.config/ecomops/config.yaml
```

Rules:

- Config errors stop execution.
- Local file errors stop execution.
- SSH errors stop execution for that source.
- Analyzer errors are warnings and do not stop other analyzers.
- AI errors are warnings and do not stop the report.

## 19. Testing Strategy

Use pytest.

Required tests:

- Config loading from YAML.
- Environment override behavior.
- Project resolution.
- Local log reader preserves line numbers.
- Parser extracts common timestamps and levels.
- PHP analyzer detects memory exhausted.
- PHP analyzer detects fatal error.
- Magento analyzer detects `report.CRITICAL`.
- Nginx analyzer detects upstream timeout.
- MySQL analyzer detects deadlock and lock wait timeout.
- Cron analyzer detects failed cron.
- Pipeline aggregates duplicate findings.
- Terminal renderer does not crash.
- JSON renderer produces valid JSON.
- CLI `analyze` works with fixture file.
- CLI handles missing file with readable error.

Test command:

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src
```

## 20. MVP Implementation Phases

### Phase 1: Project scaffold

Deliver:

- `pyproject.toml`
- package structure
- Typer entrypoint
- `ecomops --help`
- ruff/mypy/pytest config

Acceptance:

```bash
uv run ecomops --help
uv run pytest
uv run ruff check .
uv run mypy src
```

### Phase 2: Local analysis

Deliver:

- local file reader
- parser
- domain models
- PHP analyzer
- terminal report
- `ecomops analyze <file>`

Acceptance:

```bash
uv run ecomops analyze tests/fixtures/logs/php_memory.log
```

The report must include a high severity PHP memory finding with evidence.

### Phase 3: Multiple analyzers

Deliver:

- Magento analyzer
- Nginx analyzer
- MySQL analyzer
- Cron analyzer
- analyzer registry
- analyzer pipeline aggregation

Acceptance:

Fixture logs produce expected findings and counts.

### Phase 4: Config and projects

Deliver:

- YAML config loading
- `.env` loading
- project registry
- project log alias resolution
- `ecomops project list`
- `ecomops project <name> analyze <alias-or-path>`

Acceptance:

Project aliases resolve correctly from fixture config.

### Phase 5: SSH fetch

Deliver:

- Paramiko client
- SSH profile config
- remote tail fetch
- cached fetched logs
- project remote analysis

Acceptance:

Use fake/mocked SSH client in tests. Do not require a real SSH server for automated tests.

### Phase 6: Report formats

Deliver:

- JSON renderer
- Markdown renderer
- `--format json`
- `--format markdown`
- `--output <path>`

Acceptance:

Reports serialize correctly and include findings.

### Phase 7: AI enrichment

Deliver:

- AI provider protocol
- noop provider
- Ollama provider
- OpenAI provider if dependency is available
- redaction before enrichment
- `--ai`
- `--ai-provider`

Acceptance:

AI failures degrade gracefully to deterministic report.

## 21. Security Requirements

Hard requirements:

- No full logs sent to AI by default.
- Redact secrets before reports and AI.
- SSH read-only commands only.
- No sudo by default.
- Respect `known_hosts` where possible.
- Do not print `.env` secrets.
- Do not store raw fetched logs longer than configured TTL when cache cleanup exists.

CLI should clearly label AI-enriched reports:

```text
AI enrichment: enabled, provider=ollama
```

## 22. README Requirements

Create `README.md` with:

```text
# EcomOps Log Analyzer

## What It Does
## Installation
## Quick Start
## Local Log Analysis
## Project Configuration
## Remote SSH Log Fetching
## AI Enrichment
## Supported Analyzers
## Security And Privacy
## Development
## Testing
## Roadmap
## Contributing
## License
```

Quick start examples:

```bash
ecomops analyze var/log/exception.log
ecomops analyze var/log/system.log --since 24h
ecomops project noir analyze exception
ecomops project noir analyze nginx-error --remote
ecomops analyze var/log/exception.log --ai-provider ollama
```

## 23. Initial `pyproject.toml` Guidance

Use this project metadata style:

```toml
[project]
name = "ecomops-assistant"
version = "0.1.0"
description = "Terminal-first ecommerce log analysis and AI-assisted diagnostics."
requires-python = ">=3.12"
dependencies = [
  "typer>=0.12",
  "rich>=13.7",
  "pydantic>=2.7",
  "python-dotenv>=1.0",
  "pyyaml>=6.0",
  "paramiko>=3.4",
]

[project.scripts]
ecomops = "ecomops.cli.app:app"

[dependency-groups]
dev = [
  "pytest>=8.0",
  "ruff>=0.5",
  "mypy>=1.10",
]

[project.entry-points."ecomops.analyzers"]
```

## 24. Definition Of Done For MVP

The MVP is done when:

- `ecomops analyze <local-file>` works.
- At least PHP, Magento, Nginx, MySQL, and Cron analyzers exist.
- Findings include severity, category, evidence, count, root cause guess, and next steps.
- Project YAML config works.
- Remote SSH fetch can be mocked in tests and used manually.
- Terminal, JSON, and Markdown reports work.
- AI enrichment is optional and disabled by default.
- Tests cover main analyzers and CLI flows.
- README explains installation, usage, config, and security.

## 25. What Not To Build Yet

Do not build:

- web dashboard
- SaaS backend
- user accounts
- long-running agent
- alerting system
- automatic fixes
- remote write operations
- Kubernetes support
- Docker support unless explicitly requested later
- complex anomaly detection
- plugin marketplace
- SQLite history database
- Magento admin/API integration

Keep the first version practical and focused.
