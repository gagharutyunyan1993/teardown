"""Ports (interfaces) the formats context needs from the outside world.

Only Protocols live here; adapters implement them in the infrastructure layer.
"""

from __future__ import annotations

from typing import Protocol


class ByteSource(Protocol):
    """Random-access read-only bytes, e.g. a file or an in-memory buffer."""

    @property
    def size(self) -> int: ...

    def read(self, offset: int, size: int) -> bytes:
        """Return up to ``size`` bytes starting at ``offset`` (fewer at end of source)."""
        ...
