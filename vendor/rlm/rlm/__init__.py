from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from rlm.core.rlm import RLM as RLM  # noqa: F401


def __getattr__(name: str) -> Any:  # pragma: no cover
    if name == "RLM":
        return import_module("rlm.core.rlm").RLM
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["RLM"]
