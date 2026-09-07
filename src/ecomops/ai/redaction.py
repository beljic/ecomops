import re
from typing import Any

from ecomops.core.models import AnalysisReport

_BEARER_RE = re.compile(r"(?i)(\bBearer\s+)[^\s,;]+")
_AUTH_RE = re.compile(r"(?i)(\bAuthorization\s*:\s*)[^\s]+")
_KEY_VALUE_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|password|session[_-]?id)\s*([:=])\s*([^\s,;]+)"
)
_COOKIE_RE = re.compile(r"(?i)\b(cookie\s*[:=]\s*)[^\r\n]+")
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_MAGENTO_KEY_RE = re.compile(r"(?i)([?&]key=)[^&#\s]+")


def redact_sensitive_text(text: str) -> str:
    """Redact common credentials and personal data from log-derived text."""
    redacted = _BEARER_RE.sub(r"\1[REDACTED]", text)
    redacted = _AUTH_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _COOKIE_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _KEY_VALUE_RE.sub(r"\1\2[REDACTED]", redacted)
    redacted = _MAGENTO_KEY_RE.sub(r"\1[REDACTED]", redacted)
    redacted = _EMAIL_RE.sub("[REDACTED_EMAIL]", redacted)
    return _CARD_RE.sub("[REDACTED_CARD]", redacted)


def redact_report(report: AnalysisReport) -> AnalysisReport:
    """Return a report with every string field redacted before output or AI."""

    def redact_value(value: Any) -> Any:
        if isinstance(value, str):
            return redact_sensitive_text(value)
        if isinstance(value, dict):
            return {key: redact_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [redact_value(item) for item in value]
        return value

    return AnalysisReport.model_validate(redact_value(report.model_dump(mode="python")))
