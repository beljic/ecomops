from datetime import UTC, datetime

from ecomops.ai.noop import NoopProvider
from ecomops.ai.redaction import redact_report, redact_sensitive_text
from ecomops.core.models import (
    AnalysisContext,
    AnalysisReport,
    Evidence,
    Finding,
    LogSource,
    Severity,
)


def test_noop_provider_preserves_deterministic_findings() -> None:
    finding = Finding(
        id="php-memory",
        title="PHP memory exhausted",
        severity=Severity.high,
        category="php",
    )
    context = AnalysisContext(source=LogSource(type="local"))

    findings = [finding]
    result = NoopProvider().enrich_findings(findings, context)

    assert result == findings
    assert result is not findings
    assert NoopProvider().is_available() is True


def test_redaction_removes_credentials_and_sensitive_identifiers() -> None:
    text = (
        "Authorization: Bearer abc123 token=secret-value "
        "Cookie: session=abc email=person@example.test "
        "card=4111 1111 1111 1111 https://example.test/admin?key=secret"
    )

    redacted = redact_sensitive_text(text)

    assert "abc123" not in redacted
    assert "secret-value" not in redacted
    assert "person@example.test" not in redacted
    assert "4111 1111 1111 1111" not in redacted
    assert "key=secret" not in redacted
    assert "[REDACTED]" in redacted


def test_report_redaction_covers_evidence_and_source_fields() -> None:
    report = AnalysisReport(
        source=LogSource(type="local", path="https://example.test/?key=secret"),
        generated_at=datetime(2026, 9, 7, tzinfo=UTC),
        findings=[
            Finding(
                id="auth",
                title="Authorization: Bearer abc123",
                severity=Severity.high,
                category="security",
                evidence=[
                    Evidence(
                        message="token=secret-value",
                        source="person@example.test",
                        sample="Cookie: session=abc",
                    )
                ],
            )
        ],
    )

    redacted = redact_report(report)

    assert redacted.source.path == "https://example.test/?key=[REDACTED]"
    assert "abc123" not in redacted.findings[0].title
    assert "secret-value" not in redacted.findings[0].evidence[0].message
    assert "person@example.test" not in redacted.findings[0].evidence[0].source
