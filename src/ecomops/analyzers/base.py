from collections.abc import Sequence
from typing import Protocol

from ecomops.core.models import AnalysisContext, Finding, LogEntry


class Analyzer(Protocol):
    id: str

    def analyze(
        self, entries: Sequence[LogEntry], context: AnalysisContext
    ) -> list[Finding]: ...
