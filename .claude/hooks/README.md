# Hooks

Shell scripts that Claude Code runs automatically around tool calls. Nothing here is active
until it is wired into `.claude/settings.json`.

## Available

- `format-on-edit.sh` — runs Prettier / `cargo fmt` on a file after Claude edits it.
  Reads the hook payload from stdin as JSON.

## Enabling

Add a `hooks` block to `.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Edit|Write",
        "hooks": [
          {
            "type": "command",
            "command": "$CLAUDE_PROJECT_DIR/.claude/hooks/format-on-edit.sh"
          }
        ]
      }
    ]
  }
}
```

Make the script executable first:

```bash
chmod +x .claude/hooks/format-on-edit.sh
```

## Warning

Hooks execute with your user's permissions, automatically, without confirmation. Read a hook
script before enabling it. In this repository that matters more than usual: a careless hook that
logs tool payloads could write a plaintext secret to disk. Never make a hook echo file contents.
