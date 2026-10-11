"""Command-line entry point. Wires adapters to use cases; no logic of its own."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from retool import __version__
from retool.formats import InspectFile
from retool.formats.infrastructure.filesystem import FileByteSource


def _cmd_info(path: Path) -> int:
    info = InspectFile(FileByteSource(path)).execute()
    print(f"path:   {path}")
    print(f"size:   {info.size}")
    print(f"sha256: {info.sha256}")
    print(f"format: {info.format}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="retool")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    info = sub.add_parser("info", help="basic facts about a file")
    info.add_argument("path", type=Path)
    args = parser.parse_args(argv)

    if args.command == "info":
        return _cmd_info(args.path)
    return 2


if __name__ == "__main__":
    sys.exit(main())
