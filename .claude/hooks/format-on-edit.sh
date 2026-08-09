#!/usr/bin/env bash
# PostToolUse hook: format a file after Claude edits it.
# Receives the tool payload as JSON on stdin. Never echoes file contents.
set -euo pipefail

payload="$(cat)"
file_path="$(printf '%s' "$payload" | /usr/bin/python3 -c \
  'import json,sys; print(json.load(sys.stdin).get("tool_input",{}).get("file_path",""))' 2>/dev/null || true)"

[ -n "$file_path" ] && [ -f "$file_path" ] || exit 0

case "$file_path" in
  *.ts | *.tsx | *.js | *.jsx | *.json | *.css | *.md)
    command -v npx >/dev/null 2>&1 && npx --no-install prettier --write "$file_path" >/dev/null 2>&1 || true
    ;;
  *.rs)
    command -v rustfmt >/dev/null 2>&1 && rustfmt --edition 2021 "$file_path" >/dev/null 2>&1 || true
    ;;
esac

exit 0
