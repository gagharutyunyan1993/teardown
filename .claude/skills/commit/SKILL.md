---
name: commit
description: Commit the current work with a Conventional Commit message via the implementer worker (the orchestrator has no git write access). Stages only relevant files, never samples/ or secrets.
argument-hint: [optional scope or hint]
---
State:

!`git status --short | head -40`

!`git diff --stat HEAD | tail -15`

Recent subjects for style:

!`git log -5 --format='%s'`

Delegate to `implementer` with model `sonnet`, effort `low`, using the contract prompt. Fill it from the state above:
- Goal: commit the listed changes.
- Done when: `git status --short` shows nothing staged-but-uncommitted for the listed paths; commit subject follows `type(scope): summary` (feat, fix, refactor, test, docs, chore, build); hint from user: `$ARGUMENTS`.
- Context: the exact paths to stage (list them), the message you want.
- Constraints: stage by explicit path, never `-A`/`.`; never `samples/`, `.env*`, `.claude/state/`; never `--no-verify`; do not push.
- Report: hash + subject.
Reply to the user with the hash and subject only.
