"""Shared kernel: primitives every context may use. Pure; no I/O, no context imports."""

from retool.shared.errors import ParseError, RetoolError
from retool.shared.values import Address, ByteRange

__all__ = ["Address", "ByteRange", "ParseError", "RetoolError"]
