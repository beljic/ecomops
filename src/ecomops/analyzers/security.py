"""Deterministic security indicators over parsed access-log entries.

No external threat-intelligence service is called; Tor classification uses
only CIDRs configured locally in the project file.
"""

import ipaddress
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import unquote

from ecomops.ai.redaction import redact_sensitive_text
from ecomops.core.models import (
    CountItem,
    LogEntry,
    SecurityIndicator,
    SecurityScan,
    TorClassification,
)

DEFAULT_MAX_SAMPLES = 5
DEFAULT_TOP_N = 10
MAX_SAMPLE_LENGTH = 200
_STANDARD_METHODS = frozenset(
    {"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"}
)
_SCANNER_SIGNATURES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "scanner.wordpress",
        "WordPress probe on a non-WordPress route",
        re.compile(r"wp-admin|wp-login\.php|xmlrpc\.php|wp-content|wp-includes"),
    ),
    ("scanner.cgi_bin", "CGI script probe", re.compile(r"/cgi-bin/")),
    ("scanner.win_ini", "Windows file probe", re.compile(r"win\.ini|boot\.ini")),
    (
        "scanner.etc_passwd",
        "Unix system file probe",
        re.compile(r"/etc/passwd|/etc/shadow"),
    ),
    ("scanner.dotenv", "Environment file probe", re.compile(r"/\.env(?:$|[?/.])")),
    ("scanner.git", "Git metadata probe", re.compile(r"/\.git(?:$|[/?])")),
    ("scanner.traversal", "Path traversal attempt", re.compile(r"\.\.[/\\]")),
)
_LOGIN_PATH = re.compile(
    r"/customer/account/loginpost|/customer/account/login|wp-login\.php"
    r"|/index\.php/admin|/admin(?:/|$|\?)|/rest/.*/integration/(?:customer|admin)/token"
)


@dataclass
class _Evidence:
    count: int = 0
    client_ips: Counter[str] = field(default_factory=Counter)
    samples: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def add(
        self, entry: LogEntry, client_ip: str, sample: str, max_samples: int
    ) -> None:
        self.count += 1
        self.client_ips[client_ip] += 1
        if len(self.samples) < max_samples and sample not in self.samples:
            self.samples.append(sample)
        if entry.timestamp is not None:
            if self.first_seen is None or entry.timestamp < self.first_seen:
                self.first_seen = entry.timestamp
            if self.last_seen is None or entry.timestamp > self.last_seen:
                self.last_seen = entry.timestamp


def scan_security(
    entries: Sequence[LogEntry],
    *,
    tor_cidrs: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network] | None = None,
    login_threshold: int = 5,
    max_samples: int = DEFAULT_MAX_SAMPLES,
    top_n: int = DEFAULT_TOP_N,
) -> SecurityScan:
    evidence: dict[str, _Evidence] = {}
    titles: dict[str, str] = {}
    login_attempts: dict[str, _Evidence] = {}
    tor_ips: Counter[str] = Counter()
    scanned = 0
    for entry in entries:
        access = entry.access
        if access is None:
            continue
        scanned += 1
        target = unquote(access.path or "").lower()
        sample = redact_sensitive_text(access.path or "-")[:MAX_SAMPLE_LENGTH]

        matched = [
            (indicator_id, title)
            for indicator_id, title, pattern in _SCANNER_SIGNATURES
            if pattern.search(target)
        ]
        if access.method is None:
            matched.append(("request.malformed", "Malformed request line"))
        elif access.method.upper() not in _STANDARD_METHODS:
            matched.append(("request.unusual_method", "Unusual HTTP method"))
        for indicator_id, title in matched:
            titles[indicator_id] = title
            evidence.setdefault(indicator_id, _Evidence()).add(
                entry, access.client_ip, sample, max_samples
            )
        if access.method == "POST" and _LOGIN_PATH.search(target):
            login_attempts.setdefault(access.client_ip, _Evidence()).add(
                entry, access.client_ip, sample, max_samples
            )
        if tor_cidrs and _in_networks(access.client_ip, tor_cidrs):
            tor_ips[access.client_ip] += 1

    indicators = [
        _indicator(indicator_id, titles[indicator_id], item, top_n)
        for indicator_id, item in evidence.items()
    ]
    guessing = _login_guessing(login_attempts, login_threshold, max_samples, top_n)
    if guessing is not None:
        indicators.append(guessing)
    indicators.sort(key=lambda item: (-item.count, item.id))
    return SecurityScan(
        requests_scanned=scanned,
        indicators=indicators,
        tor=(
            TorClassification(
                status="checked",
                matched_requests=sum(tor_ips.values()),
                top_client_ips=_top(tor_ips, top_n),
            )
            if tor_cidrs
            else TorClassification(status="unavailable")
        ),
    )


def _login_guessing(
    attempts: dict[str, _Evidence], threshold: int, max_samples: int, top_n: int
) -> SecurityIndicator | None:
    flagged = {ip: item for ip, item in attempts.items() if item.count >= threshold}
    if not flagged:
        return None
    merged = _Evidence()
    for ip, item in flagged.items():
        merged.count += item.count
        merged.client_ips[ip] += item.count
        for sample in item.samples:
            if len(merged.samples) < max_samples and sample not in merged.samples:
                merged.samples.append(sample)
        for seen in (item.first_seen, item.last_seen):
            if seen is None:
                continue
            if merged.first_seen is None or seen < merged.first_seen:
                merged.first_seen = seen
            if merged.last_seen is None or seen > merged.last_seen:
                merged.last_seen = seen
    return _indicator(
        "login.guessing",
        f"Repeated login POSTs (>= {threshold} per client IP)",
        merged,
        top_n,
    )


def _indicator(
    indicator_id: str, title: str, item: _Evidence, top_n: int
) -> SecurityIndicator:
    return SecurityIndicator(
        id=indicator_id,
        title=title,
        count=item.count,
        top_client_ips=_top(item.client_ips, top_n),
        samples=item.samples,
        first_seen=item.first_seen,
        last_seen=item.last_seen,
    )


def _top(counter: Counter[str], top_n: int) -> list[CountItem]:
    ordered = sorted(counter.items(), key=lambda pair: (-pair[1], pair[0]))
    return [CountItem(value=value, count=count) for value, count in ordered[:top_n]]


def _in_networks(
    value: str, networks: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network]
) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in networks)
