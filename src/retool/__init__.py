"""retool: reverse-engineering toolkit.

Layout (see docs/architecture/ARCHITECTURE.md): bounded contexts as top-level
packages, each with domain / application / infrastructure layers; ``shared`` is
the shared kernel; ``interface`` holds the delivery mechanisms (CLI).
"""

__version__ = "0.1.0"
