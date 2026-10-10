"""Command-line entry point."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from retool import __version__
from retool.formats import detect


def _cmd_info(path: Path) -> int:
    with path.open("rb") as fh:
        head = fh.read(4096)
    size = path.stat().st_size
    sha = hashlib.file_digest(path.open("rb"), "sha256").hexdigest()
    print(f"path:   {path}")
    print(f"size:   {size}")
    print(f"sha256: {sha}")
    print(f"format: {detect(head)}")
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
