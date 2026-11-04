#!/usr/bin/env python3
"""Create the bundled sample config files for secret-guard.

Usage:
    python3 examples/make_sample.py [TARGET_DIR]

Default TARGET_DIR is `samples/` beside this script. Three
files are created inside it:

    mcp-config.json     a generic MCP config (Claude Code /
                        Cursor style), written as JSONC
                        with comments and a trailing comma
                        on purpose. Planted findings,
                        worked out by hand:
                          mcpServers.github.env.
                            GITHUB_TOKEN  INLINE-SECRET
                            (ghp_FAKE..., 27 chars)
                          mcpServers.weather.env.
                            SERVICE_KEY   ENV-LITERAL
                            (24-char high-entropy value
                            under a generic key name)
                          apiKey          INLINE-SECRET
                            (sk-FAKE-..., 24 chars)
                        NOT findings: GITHUB_HOST (a URL),
                        UNITS (too short, low entropy),
                        NOTES_API_KEY (already a ${...}
                        reference). Total: 3 findings,
                        scan exits 1.
    .vscode/mcp.json    a VS Code MCP config with one
                        planted INLINE-SECRET
                        (GITHUB_TOKEN, 28 chars). Because
                        the file lives under a .vscode/
                        folder, fix rewrites it with VS
                        Code's syntax: ${env:GITHUB_TOKEN}.
    clean-config.json   a config doing everything right:
                        an env reference, placeholders, an
                        empty string, an "author" key that
                        must NOT match the "auth" pattern.
                        Scan must come back CLEAN (exit 0).

Every planted secret below is FAKE — the values are
invented strings with FAKE in them, in files that exist
only to be scanned. secret-guard never prints a full
value anyway; it reports key paths and fingerprints.
"""
import sys
from pathlib import Path

LEAKY_FILES = {
    "mcp-config.json": """\
// demo fixture: an MCP config with planted FAKE secrets.
// Written as JSONC (comments, trailing comma) on purpose —
// real-world config files look like this.
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_FAKEtoken0123456789abcd",
        "GITHUB_HOST": "https://github.example.invalid"
      }
    },
    "weather": {
      "command": "python3",
      "args": ["weather_server.py"],
      "env": {
        "SERVICE_KEY": "Q7f9Kd2Lm8Zx4Vb6N1pRs3Tg",
        "UNITS": "metric"
      }
    },
    "notes": {
      "command": "node",
      "args": ["notes.js"],
      "env": {
        "NOTES_API_KEY": "${NOTES_API_KEY}"
      }
    },
  },
  "apiKey": "sk-FAKE-0123456789abcdef",
  "region": "ca-central"
}
""",
    ".vscode/mcp.json": """\
{
  "servers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "ghp_FAKEvscode0123456789wxyz"
      }
    }
  }
}
""",
    "clean-config.json": """\
{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}",
        "BACKUP_TOKEN": "your-token-here",
        "EMPTY_SECRET": ""
      }
    }
  },
  "apiKey": "<paste-your-key>",
  "author": "Jasveer Singh"
}
""",
}


def write_tree(root, files):
    root.mkdir(parents=True, exist_ok=True)
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def main():
    if len(sys.argv) > 2:
        print("usage: make_sample.py [TARGET_DIR]")
        return 2
    target = (Path(sys.argv[1]) if len(sys.argv) == 2
              else Path(__file__).parent / "samples")
    write_tree(target, LEAKY_FILES)
    print(f"Created {target}/mcp-config.json, "
          f"{target}/.vscode/mcp.json and "
          f"{target}/clean-config.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
