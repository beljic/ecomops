"""Deterministic traffic summary over parsed access-log entries."""

from collections import Counter
from collections.abc import Sequence
from datetime import UTC

from ecomops.ai.redaction import redact_sensitive_text
from ecomops.core.models import CountItem, IpStatusCounts, LogEntry, TrafficSummary

DEFAULT_TOP_N = 10
MAX_TOP_N = 50
MAX_VALUE_LENGTH = 200


def summarize_traffic(
    entries: Sequence[LogEntry], *, top_n: int = DEFAULT_TOP_N
) -> TrafficSummary:
    """Count IPs, statuses, paths, user agents, and per-minute load.

    Paths drop their query string and values are redacted and truncated, so
    tokens in URLs or user agents are not echoed back.
    """
    if not 1 <= top_n <= MAX_TOP_N:
        raise ValueError(f"top_n must be between 1 and {MAX_TOP_N}")
    client_ips: Counter[str] = Counter()
    statuses: Counter[str] = Counter()
    paths: Counter[str] = Counter()
    agents: Counter[str] = Counter()
    minutes: Counter[str] = Counter()
    statuses_by_ip: dict[str, Counter[str]] = {}
    for entry in entries:
        access = entry.access
        if access is None:
            continue
        client_ips[access.client_ip] += 1
        statuses[str(access.status)] += 1
        statuses_by_ip.setdefault(access.client_ip, Counter())[str(access.status)] += 1
        if access.path is not None:
            paths[_clean(access.path.split("?", 1)[0])] += 1
        if access.user_agent is not None:
            agents[_clean(access.user_agent)] += 1
        if entry.timestamp is not None:
            minute = entry.timestamp.astimezone(UTC).replace(second=0, microsecond=0)
            minutes[minute.isoformat()] += 1
    return TrafficSummary(
        total_requests=sum(client_ips.values()),
        unique_client_ips=len(client_ips),
        top_client_ips=_top(client_ips, top_n),
        status_counts=dict(sorted(statuses.items())),
        top_paths=_top(paths, top_n),
        top_user_agents=_top(agents, top_n),
        peak_requests_per_minute=max(minutes.values(), default=0),
        busiest_minutes=_top(minutes, top_n),
        status_by_ip=_status_by_ip(statuses_by_ip, top_n),
    )


def _status_by_ip(
    statuses_by_ip: dict[str, Counter[str]], top_n: int
) -> list[IpStatusCounts]:
    """Client IPs with 4xx/5xx responses, most errors first, bounded to top_n."""
    rows = []
    for client_ip, counts in statuses_by_ip.items():
        errors = sum(count for status, count in counts.items() if status >= "400")
        if errors:
            rows.append(
                IpStatusCounts(
                    client_ip=client_ip,
                    total_requests=sum(counts.values()),
                    error_requests=errors,
                    status_counts=dict(sorted(counts.items())),
                )
            )
    rows.sort(key=lambda row: (-row.error_requests, -row.total_requests, row.client_ip))
    return rows[:top_n]


def _top(counter: Counter[str], top_n: int) -> list[CountItem]:
    ordered = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    return [CountItem(value=value, count=count) for value, count in ordered[:top_n]]


def _clean(value: str) -> str:
    return redact_sensitive_text(value)[:MAX_VALUE_LENGTH]
