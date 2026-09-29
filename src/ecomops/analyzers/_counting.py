from collections import Counter

from ecomops.core.models import CountItem


def top_counts(counter: Counter[str], top_n: int) -> list[CountItem]:
    """The ``top_n`` most frequent values, ties ordered by value (stable JSON)."""
    ordered = sorted(counter.items(), key=lambda pair: (-pair[1], pair[0]))
    return [CountItem(value=value, count=count) for value, count in ordered[:top_n]]
