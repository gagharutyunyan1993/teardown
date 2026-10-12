"""Command-line entry point. Wires adapters to use cases; no logic of its own."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from retool import __version__
from retool.formats import (
    DEFAULT_SPACE,
    Format,
    InspectFile,
    LoadRawImage,
    RawLoadSpec,
    RawSegmentSpec,
)
from retool.formats.infrastructure.filesystem import FileByteSource
from retool.shared import Address, AddressSpace, ArchitectureId, RetoolError, SpaceAddress

_UNKNOWN_HINT = "unknown format; to load as a raw image use --raw --arch --base"
_MAX_INT_BITS = 64
_RAW_FLAGS = ("arch", "base", "offset", "length", "maps", "entry")

# (address, space name or None for the default space)
type _AddrArg = tuple[int, str | None]
# (file offset, address, file length, space name or None)
type _MapArg = tuple[int, int, int, str | None]


def _int(text: str) -> int:
    try:
        value = int(text, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected an integer (decimal or 0x hex)") from exc
    # Representational bound, not a business rule: keeps every later decimal rendering short.
    if value.bit_length() > _MAX_INT_BITS:
        raise argparse.ArgumentTypeError(f"integer exceeds {_MAX_INT_BITS} bits")
    return value


def _split_space(text: str) -> tuple[str, str | None]:
    if "@" not in text:
        return text, None
    body, _, space = text.rpartition("@")
    if not space:
        raise argparse.ArgumentTypeError("empty address space after '@'")
    return body, space


def _addr_arg(text: str) -> _AddrArg:
    body, space = _split_space(text)
    return _int(body), space


def _map_arg(text: str) -> _MapArg:
    body, space = _split_space(text)
    parts = body.split(":")
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("expected OFF:ADDR:SIZE[@SPACE]")
    off, addr, size = (_int(p) for p in parts)
    return off, addr, size, space


def _space_address(addr: int, space: str | None) -> SpaceAddress:
    named = DEFAULT_SPACE if space is None else AddressSpace(space, DEFAULT_SPACE.width_bits)
    return SpaceAddress(named, Address(addr))


def _raw_spec(args: argparse.Namespace) -> RawLoadSpec:
    arch = ArchitectureId(args.arch)
    segments: tuple[RawSegmentSpec, ...]
    if args.base is not None:
        start = SpaceAddress(DEFAULT_SPACE, Address(args.base))
        segments = (RawSegmentSpec(args.offset or 0, args.length, start),)
    else:
        maps: list[_MapArg] = args.maps
        segments = tuple(
            RawSegmentSpec(off, size, _space_address(addr, space))
            for off, addr, size, space in maps
        )
    entry = None if args.entry is None else _space_address(*args.entry)
    return RawLoadSpec(arch, segments, entry)


def _check_raw_usage(info: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if not args.raw:
        if any(getattr(args, flag) is not None for flag in _RAW_FLAGS):
            info.error("raw image flags require --raw")
        return
    if args.arch is None:
        info.error("--raw requires --arch")
    if args.base is None and args.maps is None:
        info.error("--raw requires --base or --map")
    if args.base is not None and args.maps is not None:
        info.error("--base and --map are mutually exclusive")
    if args.base is None and (args.offset is not None or args.length is not None):
        info.error("--offset and --length require --base")


def _cmd_info(path: Path) -> int:
    info = InspectFile(FileByteSource(path)).execute()
    print(f"path:   {path}")
    print(f"size:   {info.size}")
    print(f"sha256: {info.sha256}")
    print(f"format: {info.format}")
    if info.format is Format.UNKNOWN:
        print(_UNKNOWN_HINT, file=sys.stderr)
    return 0


def _cmd_info_raw(path: Path, spec: RawLoadSpec) -> int:
    info = LoadRawImage(FileByteSource(path)).execute(spec)
    print(f"path:   {path}")
    print(f"size:   {info.source_size}")
    print(f"format: {info.format}")
    print(f"arch:   {info.arch}")
    print(f"entry:  {'none' if info.entry is None else info.entry}")
    for seg in info.segments:
        print(
            f"segment {seg.name}: {seg.start} mem=0x{seg.mem_size:x} "
            f"file=0x{seg.file_start:x}+0x{seg.file_size:x}"
        )
    if info.shadowed_format is not None:
        print(
            f"warning: input starts with {info.shadowed_format} magic; "
            "loaded as raw because --raw was given",
            file=sys.stderr,
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="retool")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    info = sub.add_parser("info", help="basic facts about a file")
    info.add_argument("path", type=Path)
    info.add_argument("--raw", action="store_true", help="load as a raw image (explicit only)")
    info.add_argument("--arch", help="architecture id, required with --raw")
    info.add_argument("--base", type=_int, help="load address of the single raw segment")
    info.add_argument("--offset", type=_int, help="file offset of the --base segment")
    info.add_argument("--length", type=_int, help="file length of the --base segment")
    info.add_argument(
        "--map",
        dest="maps",
        action="append",
        type=_map_arg,
        metavar="OFF:ADDR:SIZE[@SPACE]",
        help="map file bytes at an address; repeatable",
    )
    info.add_argument("--entry", type=_addr_arg, metavar="ADDR[@SPACE]", help="entry point")
    args = parser.parse_args(argv)

    if args.command == "info":
        _check_raw_usage(info, args)
        try:
            if args.raw:
                return _cmd_info_raw(args.path, _raw_spec(args))
            return _cmd_info(args.path)
        except RetoolError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
