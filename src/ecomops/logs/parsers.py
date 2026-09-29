import ipaddress
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ecomops.core.models import AccessRequest, ClientIpSource, LogEntry, ParseStats

_PREFIX = re.compile(
    r"^\[(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)\]\s*"
    r"(?:(?P<level>[A-Za-z][A-Za-z0-9_.]*):\s*)?(?P<message>.*)$"
)
# nginx "combined" format, optionally followed by "$http_x_forwarded_for" and
# further custom fields, which are ignored.
_NGINX_ACCESS = re.compile(
    r"^(?P<socket_ip>\S+) \S+ \S+ "
    r"\[(?P<day>\d{2})/(?P<month>[A-Za-z]{3})/(?P<year>\d{4})"
    r":(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) "
    r"(?P<offset>[+-]\d{4})\] "
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    r'(?: "(?P<forwarded>[^"]*)")?)?'
)
# nginx error_log: "2026/09/03 12:00:00 [error] 1234#1234: *5 message"
_NGINX_ERROR = re.compile(
    r"^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) "
    r"\[(?P<level>[a-z]+)\] \d+#\d+: (?P<message>.*)$"
)
# Locale-independent month names for nginx $time_local.
_MONTHS = {
    name: index
    for index, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun")
        + ("Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}


@dataclass(frozen=True)
class ParseResult:
    entries: list[LogEntry]
    stats: ParseStats


def parse_lines(lines: Iterable[str], source: str) -> list[LogEntry]:
    return parse_lines_with_stats(lines, source).entries


def parse_lines_with_stats(
    lines: Iterable[str],
    source: str,
    *,
    client_ip_source: ClientIpSource = "socket",
) -> ParseResult:
    entries: list[LogEntry] = []
    level_counts: Counter[str] = Counter()
    format_counts: Counter[str] = Counter()
    for line_number, line in enumerate(lines, start=1):
        raw = line.rstrip("\r\n")
        entry = LogEntry(source=source, message=raw, raw=raw, line_number=line_number)
        match = _PREFIX.match(raw)
        if match:
            format_counts["bracketed"] += 1
            level = match["level"]
            entry = entry.model_copy(
                update={
                    "timestamp": datetime.fromisoformat(match["timestamp"]),
                    "level": level,
                    "message": match["message"],
                }
            )
            if level is not None:
                level_counts[_normalize_level(level)] += 1
        elif (error := _parse_nginx_error(raw)) is not None:
            format_counts["nginx_error"] += 1
            timestamp, level, message = error
            level_counts[_normalize_level(level)] += 1
            entry = entry.model_copy(
                update={"timestamp": timestamp, "level": level, "message": message}
            )
        else:
            access = _parse_nginx_access(raw, client_ip_source)
            if access is not None:
                format_counts["nginx_access"] += 1
                timestamp, request = access
                entry = entry.model_copy(
                    update={"timestamp": timestamp, "access": request}
                )
        entries.append(entry)
    parsed_lines = sum(format_counts.values())
    return ParseResult(
        entries=entries,
        stats=ParseStats(
            total_lines=len(entries),
            parsed_lines=parsed_lines,
            unparsed_lines=len(entries) - parsed_lines,
            level_counts=dict(level_counts),
            format_counts=dict(format_counts),
        ),
    )


def _normalize_level(level: str) -> str:
    """Drop a Monolog channel prefix and uppercase: ``main.crit`` -> ``CRIT``."""
    return level.rsplit(".", 1)[-1].upper()


def _parse_nginx_error(raw: str) -> tuple[datetime, str, str] | None:
    match = _NGINX_ERROR.match(raw)
    if match is None:
        return None
    try:
        timestamp = datetime.strptime(match["timestamp"], "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None
    return timestamp, match["level"], match["message"]


def _parse_nginx_access(
    raw: str, client_ip_source: ClientIpSource
) -> tuple[datetime, AccessRequest] | None:
    match = _NGINX_ACCESS.match(raw)
    if match is None:
        return None
    timestamp = _nginx_time(match)
    if timestamp is None:
        return None
    request_parts = match["request"].split(" ")
    method, path, protocol = (
        request_parts if len(request_parts) == 3 else (None, None, None)
    )
    forwarded_for = _valid_ips(match["forwarded"])
    socket_ip = match["socket_ip"]
    client_ip = socket_ip
    if client_ip_source == "x_forwarded_for" and forwarded_for:
        client_ip = forwarded_for[0]
    return timestamp, AccessRequest(
        client_ip=client_ip,
        socket_ip=socket_ip,
        forwarded_for=forwarded_for,
        method=method,
        path=path,
        protocol=protocol,
        status=int(match["status"]),
        bytes_sent=None if match["bytes"] == "-" else int(match["bytes"]),
        referer=_optional(match["referer"]),
        user_agent=_optional(match["user_agent"]),
    )


def _nginx_time(match: re.Match[str]) -> datetime | None:
    month = _MONTHS.get(match["month"])
    if month is None:
        return None
    offset = match["offset"]
    sign = -1 if offset[0] == "-" else 1
    delta = timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5]))
    try:
        return datetime(
            int(match["year"]),
            month,
            int(match["day"]),
            int(match["hour"]),
            int(match["minute"]),
            int(match["second"]),
            tzinfo=timezone(sign * delta),
        )
    except ValueError:
        return None


def _valid_ips(value: str | None) -> list[str]:
    if value is None:
        return []
    addresses: list[str] = []
    for candidate in value.split(","):
        candidate = candidate.strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        addresses.append(candidate)
    return addresses


def _optional(value: str | None) -> str | None:
    return None if value in (None, "", "-") else value
