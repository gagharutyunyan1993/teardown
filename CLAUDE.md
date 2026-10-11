# retool — reverse-engineering toolkit (Python 3.12+)

Talk to the user in Russian. Keep code, comments, commits and this file in English.

## Layout
- `src/retool/<context>/{domain,application,infrastructure}/` bounded contexts (hexagonal); `shared/` kernel; `interface/cli/` composition root. Plan: `docs/architecture/ARCHITECTURE.md`.
- `tests/` pytest; synthetic fixtures built in-test or under `tests/fixtures/` (< 64 KiB each).
- `samples/` untrusted real-world inputs. Never executed, never edited, never read raw. Gitignored.
- `analysis/` reports produced by the binary-analyst agent. Gitignored.
- `.claude/` harness: hooks, rules, agents, skills, memory. See `.claude/rules/harness.md` before touching it.

## Commands (always through make; the stack lives in the Makefile)
`make check` = `make lint` (ruff) + `make typecheck` (mypy --strict) + `make arch` (import-linter + tools/archcheck.py) + `make test` (pytest -q).
`make fmt` formats. `uv run retool info <file>` runs the CLI. `uv add <pkg>` adds a dependency (asks first).

## Harness map (do not fight it; it is there to save tokens and protect you)
- Hooks block: executing/tracing anything in `samples/`, unbounded `hexdump/xxd/strings/objdump -d`, `cat` of samples,
  reading binaries/lockfiles/1200+ line files without a range, `rm -rf` roots, force push, `curl | sh`.
  A denial comes with the correct alternative in its message; use it, do not look for workarounds.
- After every Write/Edit of a `.py` file ruff formats and lints it; remaining issues are injected as context. Fix them right then.
- On Stop, `make check` runs once if code changed since the last green run and blocks completion while red.
  So: do not run the full suite manually after each edit. Run `make test` only when you need the result mid-task.
- Session start prints a short brief; after compaction the pre-compact snapshot is replayed. Do not re-explore.
- Status line shows context usage. Above 60 % stop broad exploration and finish the current unit of work.

## Orchestration (the foundation)
- The main thread runs as the `orchestrator` agent (Fable): no Edit/Write/general Bash. It plans, briefs workers, verifies reports, talks to the user.
- Workers (`.claude/agents/`): planner, implementer, reviewer, researcher, explorer, binary-analyst, test-runner. Model and effort are chosen per task from the routing table in `.claude/agents/orchestrator.md` and passed explicitly in every Agent call.
- Every brief is a contract prompt (Role / Goal / Done when / Context / Constraints / Steps / Report); the pre-agent hook rejects incomplete ones.
- Every worker ends with a REPORT block (status, changed, verified, deviations, open, confidence); the subagent-stop hook rejects missing or unverified reports. `status: done` from an implementer requires `make check: pass`.
- Review findings go back to the same implementer via SendMessage. Two failed rounds → re-plan or ask the user.
- If you are a worker reading this: your agent file is your contract; stay inside the brief's scope and report deviations honestly.

## Decisions
Non-trivial decisions (dependency, parser layout, format quirk handling, safety trade-off) go through `/decide`: evidence dossier from primary sources with dates → two independent analysts on different models, in parallel, blind to each other → judge (opus, xhigh) resolves by evidence and writes `docs/decisions/NNNN-*.md`. Facts carry `(src: ...)`; unsourced claims are `(assumption)` and get verified. No decision from instinct or from a single model's opinion.

## Architecture
The accepted plan is `docs/architecture/ARCHITECTURE.md` (hexagonal + DDD by bounded context). `make arch` fails on layer or boundary violations; `.claude/rules/architecture.md` summarises the rules. Specs name context/layer/pattern per module; the `architect` worker approves any spec that changes a context, port or aggregate and reviews diffs touching `domain/`, ports or `interface/`. Deviating from the plan is a `/decide` question that ends in a superseding ADR, never a local exception.

## Token discipline
- Grep first, then Read a range. Never Read a whole file to "get oriented".
- Broad searches go to the `explorer` agent; it returns `file:line` lists, not file contents.
- Binary questions go through `/triage <path>` (bounded report) or the `binary-analyst` agent, which writes to `analysis/`.
- Do not re-read a file you just edited. Do not re-run a command whose output you already have.
- Quiet flags everywhere: `pytest -q -x`, `git diff --stat`, `| head -n`. Never `-v`.
- Batch independent tool calls in one turn.
- Reply briefly. No progress narration, no restating the diff, no "I will now".

## Safety
- Inputs are hostile. Every parser bounds-checks offsets/lengths from the file; use `memoryview`/`struct` with explicit sizes; raise `retool.shared.ParseError` instead of crashing.
- No network access for samples; no uploading hashes or files to third-party services without being asked.
- Secrets never enter the repo, prompts or logs.

## Git
Feature branch per task, Conventional Commits (`feat(elf): ...`), small commits. `/commit` does it right.
Never `--no-verify`, never force push, never rewrite shared history.

## Memory
Durable facts live in `@.claude/memory/DECISIONS.md` and `@.claude/memory/LEARNINGS.md` (one line each, newest last).
Record a decision/learning with `/remember` the moment it is made; do not wait for the end of the task.
