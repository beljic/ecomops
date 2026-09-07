# EcomOps Architecture

This document describes the public, read-only architecture. All names,
domains, paths, and credentials in examples are synthetic.

## Prompt-to-analysis flow

```mermaid
flowchart LR
    P[User prompt] --> M[MCP typed tool]
    M --> V[Validate project, alias, range, limits]
    V --> C[External project YAML]
    C --> R{Connection type}
    R -->|local| L[Bounded local reader]
    R -->|ssh| S[Restricted SSH reader]
    L --> E[LogEntry stream]
    S --> E
    E --> A[Deterministic analyzers]
    A --> O[Structured findings and report]
```

The prompt is translated into typed arguments. It never becomes a shell
command. The analyzer pipeline is independent of whether the source is local
or remote.

## Read-only security boundary

```mermaid
flowchart TD
    U[Prompt or MCP client] --> T[Typed MCP schema]
    T --> P[ReadOnlyPolicy]
    P -->|valid project and alias| B[Fixed read command builder]
    P -->|invalid or mutating request| X[Reject before SSH]
    B --> H[SSH without TTY or forwarding]
    H --> Q[Dedicated OS read-only account]
    Q --> F[Bounded log stream]
    F --> R[In-memory parser]
    R --> Y[MCP response]
```

There is no generic `execute_ssh(command)` tool. The server does not accept a
raw command, raw remote path, script, upload, SFTP write, shell redirection,
`sudo`, or remediation operation. Output is bounded by bytes, lines, timeout,
and time range. No temporary files or fetched-log cache are required.

Application-level restrictions are defense in depth, not a replacement for
permissions. The SSH account should have read-only operating-system access,
host-key verification should be enabled, and the standard package should be
installed from a trusted source. Modified code, compromised dependencies, or a
write-capable SSH account are outside the package guarantee.

## Project and source model

```mermaid
flowchart LR
    D[~/.config/ecomops/projects/] --> PC[ProjectConfig]
    PC --> LC[connection.type: local]
    PC --> SC[connection.type: ssh]
    PC --> AL[log aliases]
    LC --> LR[LocalLogSource]
    SC --> SR[SSHLogSource]
    AL --> RS[Source resolver]
    LR --> AP[Application service]
    SR --> AP
    RS --> AP
    AP --> AN[AnalyzerPipeline]
```

Each alias maps to one configured path and log type. A local project needs no
SSH credentials. An SSH password is never stored; the CLI or supported MCP
elicitation flow requests missing secrets without persisting them.

## Large-log retrieval

```mermaid
sequenceDiagram
    participant C as MCP client
    participant E as EcomOps
    participant H as Log host
    C->>E: project, alias, since, limits
    E->>E: Resolve config and validate policy
    E->>H: Fixed bounded read operation
    H-->>E: Stream only selected/bounded bytes
    E->>E: Parse in memory and stop at limits
    E-->>C: Findings, counts, range, truncation flag
```

For recent ranges, the reader takes a single bounded read from the end of a
chronological text log and filters it to the requested window; the byte and
line limits are hard bounds, not a target to expand toward. Exact arbitrary
historical ranges may require a remote scan when no index exists; either way,
the result reports incomplete sampling whenever the bounded read could not
cover the full requested window.
