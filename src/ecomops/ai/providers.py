from collections.abc import Callable

from .base import AIProvider
from .noop import NoopProvider

ProviderFactory = Callable[[], AIProvider]

_PROVIDERS: dict[str, ProviderFactory] = {"noop": NoopProvider}


def get_provider(name: str) -> AIProvider:
    """Create a configured AI provider without importing optional SDKs."""
    try:
        return _PROVIDERS[name]()
    except KeyError as error:
        available = ", ".join(sorted(_PROVIDERS))
        raise ValueError(
            f"Unknown AI provider '{name}'. Available providers: {available}."
        ) from error
