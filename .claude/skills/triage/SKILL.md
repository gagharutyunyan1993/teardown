---
name: triage
description: Bounded static first look at a file in samples/ (format, hashes, headers, sections, imports, entropy, top strings). Use before any deeper analysis of a sample; never read a sample directly.
argument-hint: <path-to-sample>
allowed-tools: Bash(bash *triage.sh *)
---
Triage report for `$ARGUMENTS`:

!`bash "${CLAUDE_SKILL_DIR}/scripts/triage.sh" $ARGUMENTS`

Summarise in at most 12 lines: format/arch/linking, packer or obfuscation signs (entropy, section names, missing imports), notable imports/strings, the single suggested next step. Do not re-run the tools above.
