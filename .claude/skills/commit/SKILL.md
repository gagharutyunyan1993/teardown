---
name: commit
description: Commit the current work with a Conventional Commit message. Stages only relevant files, never samples/ or secrets.
argument-hint: [optional scope or hint]
allowed-tools: Bash(git add *), Bash(git commit *), Bash(git status *), Bash(git diff *), Bash(git log *)
---
State:

!`git status --short | head -40`

!`git diff --stat HEAD | tail -15`

Recent subjects for style:

!`git log -5 --format='%s'`

Do:
1. Stage by explicit path (`git add src/... tests/...`). Never `git add -A`/`.`. Never stage `samples/`, `.env*`, `.claude/state/`.
2. One commit per logical change. Message: `type(scope): imperative summary` (feat, fix, refactor, test, docs, chore, build), body only if the why is not obvious. Hint from user: `$ARGUMENTS`.
3. Commit with a heredoc message. Do not push unless asked.
4. Reply with the commit hash and subject, nothing else.
