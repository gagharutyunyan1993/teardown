# Slice 2: `reporting` context + versioned JSON report (`retool info --json`)

Implements ADR 0002 surface step 1, "Shared findings plus the JSON report" (`0002:125`), and SYNTHESIS row 16, "JSON report with
input hash and per-stage hashes" (`SYNTHESIS.md:89`). Repo facts verified at 6f3b000. `architect review required`: instantiates the
planned `reporting` context (ARCH:17), adds a port (`FactSource`) and an aggregate (`Report`), grows the kernel (`check_json_value`),
grows the formats DTOs, edits `.importlinter`. Revision 3 (round 1: architect A1-A3, reviewer R1-R12; final: UNKNOWN emits no finding, test 28 phase-based).

## Scope
In: `retool.reporting` (domain/application/infrastructure); `shared.check_json_value`, also called from `Finding.__post_init__`;
formats builds its own findings (`format_facts`, DTO fields, stage constants); `retool info … --json` on both paths; `.importlinter`
contracts; the slice-1 follow-up "public `MAGIC_WINDOW`".
Out (named follow-ups): F1 text renderer in reporting (text output stays in main.py, byte-identical); F3 generator/tool-version field;
F4 ADR step 2 JSON CLI (pagination, address queries, `not_analysed` subjects); F5 section/symbol findings (no parsers yet); F6 model
id / prompt version per stage (control 8, `0002:117`); any other slice-1 follow-up.

## Architecture
Dependency direction (verified): dependencies point inward and adapters are wired only in interface (ARCH:7-8); contexts talk only
through their public `__init__` (ARCH:22; archcheck A2, `tools/archcheck.py:54-55`); application imports only domain + shared,
infrastructure imports anything (ARCH:32); a cross-context read feeding a port is "an infrastructure adapter over the public API,
never interface code", and interface "does not map DTOs" (ARCH:33); `reporting` never imports `assist` (ARCH:18).
So `reporting.domain`/`.application` import only `retool.shared` + stdlib; `reporting.infrastructure` imports the `retool.formats`
public API; `formats` never imports `reporting`. Two new contracts make this mechanical (§Import-linter). `reporting` is the planned
row ARCH:17 ("rendering analysis results (text, JSON)"): no new context, no responsibility change, no `/decide`. Facts belong to their
producer: formats builds its findings; the reporting adapter only maps DTOs.

| Module | Context / layer | Pattern (ARCH §4) | Clause |
|---|---|---|---|
| `shared/json_value.py` (+`check_json_value`) | shared kernel | pure validation fn, raises `ParseError` | ADR 0002 l.102 JsonValue; control 4 "re-validated by domain value objects" (l.109); slice-1 risk (`slice1-raw-and-findings.md:264-265`) |
| `shared/findings.py` (`Finding.__post_init__`) | shared kernel | value object validation | same |
| `formats/domain/facts.py` (new) | formats / domain | pure domain service `format_facts` | ADR 0002 l.101-104 (contexts construct findings), control 5 |
| `formats/application/{dto,use_cases}.py` | formats / application | DTO fields; per-use-case `STAGE`/`STAGE_VERSION` class constants | ARCH §4 DTOs out |
| `formats/domain/services.py` | formats / domain | public constant `MAGIC_WINDOW` | slice-1 architect note |
| `reporting/domain/model.py` | reporting / domain | read-model VOs `InputDigest`, `SegmentLayout`, `RawImageLayout`, `StageOutput`; aggregate root `Report` | ADR step 1; row 16 stage hashes |
| `reporting/domain/services.py` | reporting / domain | pure domain services (stdlib `json`/`hashlib`/`math`, no I/O) | ARCH:17; control 5 (provenance carried verbatim) |
| `reporting/domain/ports.py` | reporting / domain | Protocol `FactSource` (capability: supplies the facts to report) | ARCH:33 |
| `reporting/application/use_cases.py` | reporting / application | use case `RenderJsonReport.execute()`, orchestration only | ARCH §4 use cases |
| `reporting/infrastructure/formats_facts.py` | reporting / infrastructure | anti-corruption adapter `FormatsFactSource`: formats DTOs → reporting VOs, no rules | ARCH:33, same shape as `retool_evidence.py` (`0002:95`) |
| `reporting/__init__.py` | public API | re-exports, nothing from infrastructure (A3) | ARCH:30 |
| `interface/cli/main.py` | interface | composition root: wires `FileByteSource` → `FormatsFactSource` → `RenderJsonReport`; prints | ARCH:20,33 |

New: one port, one aggregate, no domain events. The `formats` public API grows: `FileInfo` and `RawImageInfo` gain `stage`,
`stage_version`, `findings`, `not_analysed`; `InspectFile` and `LoadRawImage` gain `STAGE`/`STAGE_VERSION`. `format_facts` stays
internal, like `build_raw_image`.

## Interfaces
Every module starts with `from __future__ import annotations`; dataclasses are `@dataclass(frozen=True, slots=True)`; error reasons
never echo values. Annotate intermediate JSON containers as `list[JsonValue]` / `dict[str, JsonValue]` (those generics are invariant).
`shared/json_value.py` (alias at l.5 unchanged; the docstring drops "no runtime validation"):
```python
MAX_JSON_DEPTH = 32                    # a top-level container is depth 1; depth > 32 rejected (assumption)
MAX_JSON_NODES = 4096                  # values incl. containers, excl. keys (assumption)
MAX_JSON_STR = 4096                    # chars per string or key (assumption)
MAX_JSON_TEXT = 1 << 16                # total chars over all strings + keys of one value (assumption)
JSON_INT_MIN, JSON_INT_MAX = -(1 << 63), (1 << 64) - 1   # (assumption) 64-bit addresses fit
def check_json_value(value: object) -> None: ...         # ParseError, offset None
```
`shared/__init__.py`: import + `__all__` gain `check_json_value` (13 names; constants stay out). `shared/findings.py`:
`Finding.__post_init__` calls `check_json_value(self.value)` after the producer check. Step 0 before this edit: run
`grep -rn "Finding(" src tests`. At 6f3b000 it hits only `tests/shared/test_findings.py:53` (value `1`) and `:80` (a valid dict),
so no edits are expected. Any other hit with a non-JSON value: stop and report.
`formats/domain/facts.py` (imports `Format` and `retool.shared` only):
```python
def format_facts(fmt: Format, producer: str) -> tuple[tuple[Finding, ...], tuple[NotAnalysed, ...]]: ...
```
| `fmt` | findings (subject `"input"`, `Provenance.PARSED`, `Verification.unverified()`, `producer`) | not_analysed |
|---|---|---|
| ELF, PE, MACHO | value `{"magic": fmt.value}` | `f"container structure not parsed: no {fmt.value} parser in this version"` |
| UNKNOWN | none (no known magic was read; architect ruling) | `"container structure not parsed: unknown format"` |
| RAW | none | `"raw image content not analysed"` |
`formats/application/dto.py`: `FileInfo` and `RawImageInfo` each append the fields `stage: str; stage_version: str;
findings: tuple[Finding, ...]; not_analysed: tuple[NotAnalysed, ...]` (no defaults). They are constructed only at `use_cases.py:34,47`.
`formats/application/use_cases.py`:
- `InspectFile` gets `STAGE: Final = "formats.inspect"; STAGE_VERSION: Final = "1"`, and `LoadRawImage` gets
  `STAGE: Final = "formats.raw"; STAGE_VERSION: Final = "1"`. Bump `STAGE_VERSION` when the use case's facts for the same input change.
- `InspectFile.execute` fills the new fields from `format_facts(detect(head), self.STAGE)`. `LoadRawImage.execute` fills them from
  `format_facts(image.format, self.STAGE)` (always RAW).
- `MAGIC_WINDOW` fold-in: in `formats/domain/services.py` rename `_HEADER_LEN` (l.14; used l.33) to `MAGIC_WINDOW = 4` with
  `# every magic detect() knows is <= MAGIC_WINDOW bytes`. In `use_cases.py` delete `_MAGIC_WINDOW` (l.14), import `MAGIC_WINDOW`
  from services (l.10), use it at l.46. Not exported from `retool.formats`.
`reporting/domain/model.py`. Its types are a read model: display values only, with no lookup, overlap or containment behaviour. They
are not `MemoryMap`/`Image` in reporting's signatures, so the ADR 0001 revisit trigger (`0001:116`) does not fire.
```python
SCHEMA_VERSION = 1
MAX_STAGES = 16; MAX_FINDINGS = 4096; MAX_NOT_ANALYSED = 256   # report bounds (assumption)
MAX_IMAGE_SEGMENTS = 64     # reporting's own output bound: keeps raw_image to ~10 KiB of JSON (assumption)
_SEGMENT = re.compile(r"[a-z0-9_.-]{1,32}")     # reporting's own output charset: plain ASCII, no escapes needed (assumption)
_STAGE = re.compile(r"[a-z0-9_.:-]{1,64}")      # stage names are Finding producers, so the same charset (findings.py:15)
_VERSION = re.compile(r"[0-9a-z_.+-]{1,32}")    # (assumption)
_SHA256 = re.compile(r"[0-9a-f]{64}")
class InputDigest:    sha256: str; size: int    # _SHA256.fullmatch; size >= 0
class SegmentLayout:  name: str; start: SpaceAddress; mem_size: int; file_start: int; file_size: int
    # _SEGMENT.fullmatch (name not echoed); mem_size >= 1; file_start >= 0; file_size >= 0
class RawImageLayout: arch: ArchitectureId; entry: SpaceAddress | None; segments: tuple[SegmentLayout, ...]
    # 1 <= len(segments) <= MAX_IMAGE_SEGMENTS
class StageOutput:    name: str; version: str; findings: tuple[Finding, ...] = ()
                      not_analysed: tuple[NotAnalysed, ...] = (); raw_image: RawImageLayout | None = None
    # _STAGE / _VERSION fullmatch; every finding.producer == name ("producer does not match stage")
class Report:         input: InputDigest; stages: tuple[StageOutput, ...]
    # 1..MAX_STAGES ("stage count"); unique names ("duplicate stage"); <= 1 stage with raw_image ("raw image");
    # sum(findings) <= MAX_FINDINGS ("finding count"); sum(not_analysed) <= MAX_NOT_ANALYSED ("not-analysed count")
    @property
    def raw_image(self) -> RawImageLayout | None: ...   # the single stage's layout, else None
```
`reporting/domain/services.py`:
```python
MAX_REPORT_CHARS = 1 << 23          # 8 MiB of JSON text per encoding, trailing newline excluded; ASCII so chars == bytes (assumption)
def stage_sha256(stage: StageOutput) -> str: ...    # re-validates each Finding.value first (Safety 2)
def render_json(report: Report) -> str: ...         # calls stage_sha256 for every stage before building the document
```
`reporting/domain/ports.py`: `class FactSource(Protocol): def collect(self) -> Report: ...`
`reporting/application/use_cases.py`: `class RenderJsonReport`: `__init__(self, facts: FactSource) -> None`;
`execute(self) -> str` returns `render_json(self._facts.collect())`.
`reporting/infrastructure/formats_facts.py`: `class FormatsFactSource: __init__(self, source: ByteSource, raw: RawLoadSpec | None
= None) -> None; collect(self) -> Report`. `collect` maps DTOs only:
1. If `raw`: `raw_info = LoadRawImage(source).execute(raw)` first. Spec errors then fail before any read: `build_raw_image` runs at
   `use_cases.py:45`, before the read at l.46, as pinned by `tests/formats/test_load_raw.py:23-27` (`past.calls == []`).
2. `info = InspectFile(source).execute()`.
3. TOCTOU guard: if `raw` and `raw_info.source_size != info.size`, raise `ParseError("input changed during read")`.
   InspectFile also raises ParseError('input changed during read') on short read.
4. Inspect stage: `StageOutput(info.stage, info.stage_version, info.findings, info.not_analysed)`. Raw stage:
   `StageOutput(raw_info.stage, raw_info.stage_version, raw_info.findings, raw_info.not_analysed, RawImageLayout(raw_info.arch,
   raw_info.entry, tuple(SegmentLayout(s.name, s.start, s.mem_size, s.file_start, s.file_size) for s in raw_info.segments)))`.
   `format` and `shadowed_format` are not mapped (the inspect finding carries the magic).
5. Return `Report(InputDigest(info.sha256, info.size), (inspect, raw?))`. No try/except: formats raises `RetoolError`, and
   `FileByteSource` translates `OSError` (slice 1).
`reporting/__init__.py` exports `FactSource, InputDigest, RawImageLayout, RenderJsonReport, Report, SCHEMA_VERSION, SegmentLayout,
StageOutput, render_json, stage_sha256`.

## JSON schema (schema_version 1)
One top-level object with exactly six keys:
- `schema_version`: int `1`. Any change to existing keys, types or meaning bumps it; in v1, additive keys bump it too (assumption).
- `input`: `{"sha256": <64 lowercase hex of the whole input>, "size": <int bytes>}`.
- `stages`: in execution order, `[{"name": str, "version": str, "sha256": <stage_sha256>}]`.
- `findings`: stage order, then tuple order: `[{"subject": str, "value": JsonValue, "provenance": "parsed"|"disassembled"|"inferred"|
  "llm_suggested", "verification": {"status": "unverified"|"passed"|"rejected", "checks": [str], "reason": str}, "producer": str}]`;
  all keys always present (`checks: []`, `reason: ""` when unused).
- `not_analysed`: `[{"reason": str, "stage": <owning StageOutput.name>}]`. The `stage` key is a reporting addition, since
  `NotAnalysed` has only `reason` (assumption).
- `raw_image`: `null` without `--raw`; else `{"arch": str, "entry": "space:0xhex"|null, "segments": [{"name": str, "start":
  "space:0xhex", "mem_size": int, "file_start": int, "file_size": int}]}`. Addresses are `str(SpaceAddress)` (`values.py:96-97`);
  offsets/sizes are decimal ints. The layout is user-declared (ADR 0001), so it is not a Finding and has no provenance.
Never present: path, file name, timestamps, host, tool version.
Encoding: `render_json` = `json.JSONEncoder(sort_keys=True, ensure_ascii=True, allow_nan=False, indent=2)` text + one `"\n"`.
`stage_sha256(s)` = sha256 hexdigest of the ASCII canonical encoding (`sort_keys=True, ensure_ascii=True, allow_nan=False,
separators=(",", ":")`) of `{"name", "version", "findings": [...], "not_analysed": [...], "raw_image": obj|null}`. The object holds
only that stage's fragments, exactly as rendered, so a version bump changes the hash.
Golden documents (recomputed in a scratch run for revision 3; golden file = `json.dumps(json.loads(LINE), indent=2, sort_keys=True) + "\n"`).
G1 `tests/fixtures/reporting/elf_magic.json`: input `b"\x7fELF" + b"\0"*60`, `info PATH --json`:
```
{"findings":[{"producer":"formats.inspect","provenance":"parsed","subject":"input","value":{"magic":"elf"},"verification":{"checks":[],"reason":"","status":"unverified"}}],"input":{"sha256":"cc9d6fac1f314ccbd3003c6a0e788a426958609b1312422d8fed40a08ee0bb51","size":64},"not_analysed":[{"reason":"container structure not parsed: no elf parser in this version","stage":"formats.inspect"}],"raw_image":null,"schema_version":1,"stages":[{"name":"formats.inspect","sha256":"c3317479b496443b1218c8fab2e1b0c782501ebbf56a3003b29b1b2b11be1bee","version":"1"}]}
```
G2 `tests/fixtures/reporting/raw_base.json`: input `b"\0"*0x100`, `info PATH --json --raw --arch armv7 --base 0x8000000`:
```
{"findings":[],"input":{"sha256":"5341e6b2646979a70e57653007a1f310169421ec9bdd9f1a5648f75ade005af1","size":256},"not_analysed":[{"reason":"container structure not parsed: unknown format","stage":"formats.inspect"},{"reason":"raw image content not analysed","stage":"formats.raw"}],"raw_image":{"arch":"armv7","entry":null,"segments":[{"file_size":256,"file_start":0,"mem_size":256,"name":"seg0","start":"ram:0x8000000"}]},"schema_version":1,"stages":[{"name":"formats.inspect","sha256":"4821dc0c02e0eaba4f1789b3b08c5ed6360fc5a26261ccdbd785c5429d0f0152","version":"1"},{"name":"formats.raw","sha256":"92cfbecff776298495722c94cefc74ad272b40ed48a21fee43af22719186c841","version":"1"}]}
```

## Files
Create: `src/retool/reporting/__init__.py`, `src/retool/reporting/{domain,application,infrastructure}/__init__.py` (empty),
`src/retool/reporting/domain/{model,services,ports}.py`, `src/retool/reporting/application/use_cases.py`,
`src/retool/reporting/infrastructure/formats_facts.py`, `src/retool/formats/domain/facts.py`, `tests/shared/test_json_value.py`,
`tests/formats/test_facts.py`, `tests/reporting/__init__.py`, `tests/reporting/{fakes,test_model,test_render,test_use_case,test_formats_facts}.py`,
`tests/fixtures/reporting/{elf_magic,raw_base}.json`.
Modify: `src/retool/shared/json_value.py` (l.1, append), `src/retool/shared/findings.py` (`Finding.__post_init__` l.90-100),
`src/retool/shared/__init__.py` (l.5, `__all__` l.8-21), `src/retool/formats/domain/services.py` (l.14, l.33),
`src/retool/formats/application/dto.py` (`FileInfo` l.11-15, `RawImageInfo` l.27-36), `src/retool/formats/application/use_cases.py`
(l.7-14, l.17-34, l.37-63), `src/retool/interface/cli/main.py` (imports l.10-19, `info` args l.138-152, dispatch l.157-160, new
`_cmd_info_json`), `.importlinter`. Append-only: `tests/shared/test_findings.py`, `tests/interface/test_cli.py`,
`tests/formats/test_detect.py`. Do not touch `docs/` or `tests/formats/test_{inspect,load_raw}.py`.

## Safety
1. `check_json_value` walks the value iteratively with an explicit stack (no recursion). Rules and reasons (test substrings):
   - exact types only (`type(v) is …`: None, bool, int, float, str, list, dict); tuple/set/bytes/StrEnum/subclasses -> `json value has unsupported type`.
   - ints in `[JSON_INT_MIN, JSON_INT_MAX]` (`json int out of range`); floats `math.isfinite` (`json float not finite`); keys
     `type(k) is str` (`json key not a string`).
   - each string/key <= MAX_JSON_STR (`json string too long`); running total of string + key chars <= MAX_JSON_TEXT
     (`json text budget exceeded`); strict UTF-8 encodable, so lone surrogates in values or keys are rejected
     (`json string not valid unicode`).
   - depth: a top-level container is depth 1, each nested container +1, depth > MAX_JSON_DEPTH -> `json value too deep` (also rejects cycles).
   - nodes: the top-level value counts 1; before pushing a container's children, `nodes + len(container) > MAX_JSON_NODES` ->
     `json value has too many nodes`, else `nodes += len(container)`. The stack therefore never exceeds the cap, and wide or
     self-referencing containers fail in O(cap) (`[0]*10_000_000` fails at once).
2. Defence in depth: `stage_sha256` re-runs `check_json_value` on each of its stage's `Finding.value`s, because list/dict values stay
   mutable after construction. `render_json` hashes every stage first, so every value is re-checked before encoding.
3. Output cap: both encodings stream `iterencode` chunks with a running total. Past `MAX_REPORT_CHARS` they raise
   `ParseError(f"report exceeds {MAX_REPORT_CHARS} chars")` at once, so memory stays bounded by the cap. There is no separate
   "not encodable" branch: Safety 1-2 leave the encoder no invalid input.
4. Terminal safety: `ensure_ascii=True` escapes every char outside 0x20-0x7e as `\uXXXX`, including C0 controls, DEL 0x7f
   (verified: `json.dumps("\x7f\x1b‮")` gives `"\u007f\u001b‮"`), bidi and non-ASCII. stdout holds no raw control char
   other than `\n`.
5. Determinism: `sort_keys` at every level; arrays in stage/tuple order; no clock, path, host, PID, randomness or dict insertion order.
6. No path echo: the report never contains the input path or name; reporting `ParseError`s carry no value text.
7. Bounded work: count caps are checked in `Report.__post_init__` before rendering. Reads are slice 1's only: the magic window plus
   `InspectFile`'s chunked 1 MiB hash and 4096-byte head (`use_cases.py:12-13,27-33`). The TOCTOU guard rejects an input whose size
   differs between the raw load and the hash.

## CLI
`retool info PATH [--json] [raw flags as in slice 1]`. `--json` is `action="store_true"`, help "print a versioned JSON report". It
is not in `_RAW_FLAGS` (main.py:23), so `_check_raw_usage` (main.py:86-98) is unchanged and runs first: usage errors exit 2 with
nothing on stdout.
- First line inside the existing `try` (main.py:157-163): `if args.json: return _cmd_info_json(args.path, _raw_spec(args) if args.raw else None)`.
- `_cmd_info_json(path: Path, spec: RawLoadSpec | None) -> int`:
  `sys.stdout.write(RenderJsonReport(FormatsFactSource(FileByteSource(path), spec)).execute())`; `return 0`. Nothing is written
  before `execute()` returns, so a `RetoolError` gives the existing `error: …` on stderr, exit 1, empty stdout.
- JSON mode prints neither the UNKNOWN hint nor the raw magic warning; the report carries both facts (assumption). Without
  `--json`, output is byte-identical to slice 1.
- New imports: `from retool.reporting import RenderJsonReport`; `from retool.reporting.infrastructure.formats_facts import FormatsFactSource`.

## Tests
Fakes (`tests/reporting/fakes.py`): `fnd(value, producer="s", provenance=PARSED, verification=Verification.unverified()) -> Finding`
(subject "input"); `stage(name="s", version="1", findings=(), not_analysed=(), raw_image=None) -> StageOutput`;
`digest = InputDigest("0"*64, 0)`; `FakeFacts(report_or_exc)` counting `calls`; `GrowingSource(data)`, whose `size` is `len(data)`
until its first `read()` call and `len(data) + 16` from then on, however often `size` is accessed (reads return zeros up to the current size). Formats fakes come from `tests/formats/fakes.py`.
`tests/shared/test_json_value.py`:
1. `test_check_json_value_accepts` [None, True, 0, JSON_INT_MIN, JSON_INT_MAX, 1.5, -0.0, "", "ж", "\x1b[2J", `{"a": [1, 2.5, None, True, "x"]}`, 32 nested lists, 32 nested `{"k": …}` dicts, `list(range(4095))`, `["a"*4096]*16`] -> None.
2. `test_check_json_value_rejects` [nan/inf/-inf -> `not finite`; `{1: "x"}` -> `key not a string`; `(1,)`, `b"x"`, `{"a"}`, a local `StrEnum` member -> `unsupported type`; JSON_INT_MAX+1, JSON_INT_MIN-1 -> `int out of range`; `"a"*4097`, `{"k"*4097: 0}` -> `string too long`; `"\ud800"`, `{"\ud800": 0}` -> `not valid unicode`; 33 nested lists, 33 nested `{"k": …}` dicts -> `too deep`; `list(range(4096))` -> `too many nodes`; `["a"*4096]*16 + ["b"]`, `{c*4096: 0 for c in "abcdefghijklmnopq"}` (17 keys) -> `text budget exceeded`] -> ParseError with the substring, `exc.offset is None`, `"a"*100` not in `str(exc)`.
3. `test_check_json_value_cycles_and_width`: `a=[]; a.append(a)` and `d={}; d["k"]=d` -> `too deep`; `b=[]; b.extend([b]*1000)`, `{str(i): 0 for i in range(100_000)}`, `[0]*10_000_000` -> `too many nodes`.
4. `test_finding_validates_value` (append to `tests/shared/test_findings.py`): `Finding` with value nan, 33-deep, `{1: 2}` -> ParseError.
`tests/formats/test_facts.py` (fact content lives here):
5. `test_format_facts_structured` [ELF, PE, MACHO]: `format_facts(fmt, "p") == ((Finding("input", {"magic": fmt.value}, Provenance.PARSED, Verification.unverified(), "p"),), (NotAnalysed(f"container structure not parsed: no {fmt.value} parser in this version"),))`.
6. `test_format_facts_unknown`: `format_facts(Format.UNKNOWN, "p") == ((), (NotAnalysed("container structure not parsed: unknown format"),))`.
7. `test_format_facts_raw`: `== ((), (NotAnalysed("raw image content not analysed"),))`; for every `Format`, no reason contains `disassembl`.
8. `test_inspect_file_stage_fields`: `MemorySource(b"\x7fELF"+b"\0"*60)` -> `info.stage == InspectFile.STAGE == "formats.inspect"`, `stage_version == "1"`, `(info.findings, info.not_analysed) == format_facts(Format.ELF, "formats.inspect")`.
9. `test_load_raw_stage_fields`: ELF bytes, `seg(0, None, sa(ram, 0))` -> `stage == LoadRawImage.STAGE == "formats.raw"`, `stage_version == "1"`, `findings == ()`, `not_analysed == (NotAnalysed("raw image content not analysed"),)`.
10. `test_magic_window_public` (append to `test_detect.py`): `MAGIC_WINDOW == 4` and `detect(b"\x7fELF"[:MAGIC_WINDOW]) is Format.ELF`.
`tests/reporting/test_model.py` (domain):
11. `test_input_digest`: `("a"*64, 0)` ok; `("", 0)`, `("A"*64, 0)`, `("g"*64, 0)`, `("a"*63, 0)`, `("a"*64, -1)` -> ParseError.
12. `test_stage_output_rejects`: name [`""`, `"Bad Name"`, `"a"*65`]; version [`""`, `"1 0"`, `"a"*33`]; `stage("s", findings=(fnd(1, "other"),))` -> `producer does not match stage`.
13. `test_report_limits`: reject `stages=()`, 17 stages, duplicate names, two raw_image stages, findings 2048+2049 over two stages, 257 not_analysed; accept 16 stages, 4096 findings, 256 not_analysed; `report.raw_image` returns the one layout or None.
14. `test_raw_image_layout_rejects`: `segments=()`; 65 segments; name `"Bad\x1b"` (not in message); mem_size 0; file_start -1; file_size -1.
`tests/reporting/test_render.py` (domain):
15. `test_schema_keys_and_version`: top-level keys == the six; `schema_version == SCHEMA_VERSION == 1`.
16. `test_render_provenance_and_verification`: one stage, findings (PARSED, unverified), (DISASSEMBLED, passed(("a",))), (INFERRED, rejected("r")), (LLM_SUGGESTED, unverified) -> provenances `["parsed", "disassembled", "inferred", "llm_suggested"]`; verifications exactly `{"checks": [], "reason": "", "status": "unverified"}`, `{"checks": ["a"], "reason": "", "status": "passed"}`, `{"checks": [], "reason": "r", "status": "rejected"}`, and the unverified one again.
17. `test_render_deterministic`: rendering twice gives equal text; `{"b":1,"a":2}` vs `{"a":2,"b":1}` give identical text and `stage_sha256`.
18. `test_render_escapes_to_ascii`: value `"\x1b[2J\x7f‮ ж"` -> `text.isascii()`; `re.search(r"[\x00-\x09\x0b-\x1f\x7f]", text) is None`; `"\\u001b"`, `"\\u007f"`, `"\\u202e"` in text; `json.loads` round-trips.
19. `test_render_single_document`: `text.endswith("}\n")`, no `"\n\n"`; `json.loads(text)` succeeds.
20. `test_stage_sha256_canonical`: two stages; recompute each hash in-test from `json.loads(text)` fragments plus name/version with the canonical `json.dumps` -> equals `stages[i]["sha256"]`; changing a finding of stage 2 changes only stage 2's hash; `stage(version="2")` changes the hash.
21. `test_render_revalidates_mutated_value`: `f = fnd({"a": []})`; append `float("nan")` to `f.value["a"]` (narrow with `isinstance`) -> `render_json` and `stage_sha256` raise ParseError `not finite`.
22. `test_output_cap`: `big = tuple(fnd(["\x01"*4096]*16) for _ in range(4096))` -> `stage_sha256(stage(findings=big))` and `render_json` of that report raise `report exceeds`; small report with `monkeypatch.setattr(services, "MAX_REPORT_CHARS", len(text) - 1)` ok, `len(text) - 2` -> ParseError.
`tests/reporting/test_use_case.py` (application):
23. `test_render_json_report`: `RenderJsonReport(FakeFacts(r)).execute() == render_json(r)`; `calls == 1`.
24. `test_render_json_report_propagates`: `FakeFacts(ParseError("x"))` -> the same ParseError.
`tests/reporting/test_formats_facts.py` (infrastructure, mapping only; expected values taken from the formats DTOs, not literals):
25. `test_maps_inspect_dto`: `data = b"\x7fELF"+b"\0"*60`; `info = InspectFile(MemorySource(data)).execute()` -> `collect().input == InputDigest(info.sha256, info.size)`, `stages == (StageOutput(info.stage, info.stage_version, info.findings, info.not_analysed),)`, `raw_image is None`.
26. `test_maps_raw_dto`: `b"\0"*0x100`, spec `seg(0, 0x80, sa(ram, 0))`, `seg(0x80, 0x80, sa(bank1, 0x4000))`, entry `sa(bank1, 0x4000)` -> stage names `(InspectFile.STAGE, LoadRawImage.STAGE)`; `raw_image == RawImageLayout(arm, sa(bank1, 0x4000), (SegmentLayout("seg0", sa(ram, 0), 0x80, 0, 0x80), SegmentLayout("seg1", sa(bank1, 0x4000), 0x80, 0x80, 0x80)))`; raw stage findings/not_analysed equal `LoadRawImage(...).execute(spec)`'s.
27. `test_raw_spec_error_before_hashing`: `SparseSource(1 << 31)`, `seg(1 << 31, None, sa(ram, 0))` -> ParseError and `calls == []` (guaranteed by `use_cases.py:45-46`, pinned by `test_load_raw.py:23-27`).
28. `test_input_changed_during_read`: `GrowingSource(b"\0"*16)` with `seg(0, None, sa(ram, 0))` -> ParseError `input changed during read`.
`tests/interface/test_cli.py` (append; `FIXTURES = Path(__file__).parent.parent / "fixtures" / "reporting"`):
29. `test_info_json_golden_elf`: G1 -> exit 0; `out == (FIXTURES / "elf_magic.json").read_text()`; `err == ""`.
30. `test_info_json_golden_raw`: G2 -> exit 0; `out == raw_base.json`; `err == ""`.
31. `test_info_json_raw_multi_map_entry`: `b"\0"*0x100`, `--json --raw --arch armv7 --map 0:0x0:0x80 --map 0x80:0x4000:0x80@bank1 --entry 0x4000@bank1` -> `'"entry": "bank1:0x4000"' in out`, `'"start": "bank1:0x4000"' in out`, and `json.loads(out)["raw_image"]["segments"]` == two dicts (`seg0` `ram:0x0` 128/0/128, `seg1` `bank1:0x4000` 128/128/128).
32. `test_info_json_deterministic_no_path`: the same bytes as `secret-a.bin` and `secret-b.bin` -> identical stdout; neither `"secret"` nor `str(tmp_path)` in stdout.
33. `test_info_json_stdout_is_one_document` [ELF bytes; `b"\0"*16`; ELF bytes with `--raw --arch armv7 --base 0`]: `out == json.dumps(json.loads(out), indent=2, sort_keys=True) + "\n"`; `err == ""`.
34. `test_info_json_usage_errors` [`--json --arch armv7`; `--json --raw --base 0`; `--json --raw --arch armv7`; `--json --base 0`] -> `SystemExit` code 2; stdout `""`.
35. `test_info_json_errors_exit_1` [`--raw --arch armv7 --base 0 --offset 0x100` on a 16-byte file; a missing path], each with `--json` -> exit 1; stdout `""`; stderr starts `error:`.

## Import-linter
Verified on a scratch copy (import-linter 2.15, stub `reporting` packages): 8 kept, 0 broken; adding `import retool.formats` to
`reporting/application` broke the format-agnostic contract as intended.
1. `no-infra-in-core` (`.importlinter:15-22`): sources += `retool.reporting.domain`, `retool.reporting.application`; forbidden +=
   `retool.reporting.infrastructure` (mirrors §7 item 1, ARCH:66).
2. `shared-kernel-pure` (l.25-33): forbidden += `retool.reporting`.
3. `no-interface-from-contexts` (l.36-43): sources += `retool.reporting`.
4. `no-assist-in-deterministic` (l.48-54): sources += `retool.reporting` (ARCH:65,67, item 2 "in the change that creates each one").
5. Append three contracts (same keys and layout as `layers-formats`, l.5-12, and the existing `forbidden` contracts):
   - `[importlinter:contract:layers-reporting]`, name `reporting: interface -> application -> domain`, `type = layers`, layers
     `retool.reporting.infrastructure`, `retool.reporting.application`, `retool.reporting.domain`, `containers =` (empty).
   - `[importlinter:contract:reporting-core-format-agnostic]`, name `reporting domain/application do not import formats`, `type =
     forbidden`, sources `retool.reporting.domain`, `retool.reporting.application`, forbidden `retool.formats`; comment
     `# ARCH §3: reporting core reads formats only through an infrastructure adapter.`
   - `[importlinter:contract:formats-upstream-of-reporting]`, name `formats does not import reporting`, `type = forbidden`, source
     `retool.formats`, forbidden `retool.reporting`; comment `# Dependency direction: formats is upstream of reporting.`

## Risks
- Kernel growth (architect): `check_json_value` plus the `Finding` call. If rejected, keep only Safety 2 (re-validation in
  `stage_sha256`) and drop the `Finding` call and the export.
- ADR 0002 revisit trigger (`0002:144`) stays unfired: `formats` now builds its own findings (`format_facts`), and `assist` builds
  LLM_SUGGESTED findings by design (`0002:104`). That makes two constructing contexts, with `reporting` only carrying them.
- The raw layout stays outside findings because ADR 0002 l.99 has no "declared" tier; adding one is a `/decide`.
- `STAGE_VERSION` bumps are manual; the stage hash includes the version, so a forgotten bump still shows as a hash change.
- Raw `--json` hashes the whole input (chunked, O(size) time, bounded memory), unlike raw text output (slice 1 Out).
- archcheck A6 flags the word `Any` in docstrings too (`archcheck.py:76-78`). `iterencode` with indent recurses in pure Python;
  depth is at most about 5 + 32, which is safe. Every cap value is an assumption.

## Acceptance
1. `make check` passes; lint-imports prints `Contracts: 8 kept, 0 broken.`; archcheck prints `archcheck: ok`.
2. Tests 1-35 exist under the names above and pass; no existing test body is edited (new tests are appended).
3. `grep -rn "retool.formats" src/retool/reporting/domain src/retool/reporting/application` and
   `grep -n "infrastructure" src/retool/reporting/__init__.py` print nothing; `grep -rn "Finding(" src/retool/reporting` prints nothing.
4. `grep -rnE "_MAGIC_WINDOW|_HEADER_LEN" src/` prints nothing; `grep -v '^\s*#' src/retool/formats/application/use_cases.py | grep -c MAGIC_WINDOW`
   prints 2; `test_check9_bounded_reads` (`tests/formats/test_load_raw.py:18-21`, `calls == [(0, 4)]`) passes unchanged.
5. `retool.shared.__all__` is the 12 slice-1 names plus `check_json_value`; `grep -c "Format.RAW" src/retool/formats/domain/services.py` still prints 1.
6. Both golden files pass `jq empty`, are under 64 KiB, and equal G1/G2 under the stated transform; the five `sha256` values in
   them match this spec verbatim.
7. `grep -nE "struct\.|ByteRange\(|json\." src/retool/interface/cli/main.py` prints nothing (A7; interface only wires).
8. `git diff --stat` lists only the files in `## Files`.
