---
name: fetch
description: Fetch a documentation page through the session proxy as bounded plain text (works where the built-in WebFetch fails with ENOTFOUND). Use for spec lookups; add a grep pattern to keep only the relevant part.
argument-hint: <https-url> [max-lines] [grep-pattern]
---
!`bash "${CLAUDE_SKILL_DIR}/scripts/fetch.sh" $ARGUMENTS`

Cite facts from this as `(src: <url>, fetched <date>)`.
