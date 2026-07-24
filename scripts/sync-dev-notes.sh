#!/usr/bin/env bash
# Mirror the private auto-memory dev notes into docs/dev-notes/ (tracked in the
# repo). Installed as a pre-commit hook so the mirror stays current on every
# commit; also safe to run by hand: `bash scripts/sync-dev-notes.sh`.
#
# Redaction is heuristic and context-based (no secret literal is stored here):
# it scrubs "admin / <pw>" and "password is `<pw>`" phrasings. It is NOT a
# general secret scanner — do not paste real credentials into the notes.
set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
MEM="${QW_MEMORY_DIR:-$HOME/.claude/projects/H--quantawatch/memory}"
DEST="$REPO/docs/dev-notes"
TOKEN='<redacted-see-local-config>'   # no space/dot/paren -> redaction is idempotent

if [ ! -d "$MEM" ]; then
  echo "sync-dev-notes: memory dir '$MEM' not found, skipping"
  exit 0
fi

mkdir -p "$DEST"
# README.md in DEST is repo-authored; the memory dir has none, so it is preserved.
cp "$MEM"/*.md "$DEST"/

for f in "$DEST"/*.md; do
  sed -i -E "s#(admin / )[^ .)]+#\\1$TOKEN#g" "$f"
  sed -i -E "s#(password is \`)[^\`]+#\\1$TOKEN#g" "$f"
  # Wikilinks -> markdown links so they navigate on GitHub.
  sed -i -E 's/\[\[([A-Za-z0-9_-]+)\]\]/[\1](\1.md)/g' "$f"
done

git add "$DEST"
