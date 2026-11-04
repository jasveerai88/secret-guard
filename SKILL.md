---
name: secret-guard
description: Find inline secrets in AI-agent / MCP config files and fix them by rewriting each literal into an environment-variable reference. `secret-guard scan FILE...` checks JSON/JSONC configs (Claude Code settings, .mcp.json, VS Code mcp.json, Cursor-style, generic) with exactly two rules — a secret-NAMED key (token, secret, password, passwd, auth, authorization, bearer, apikey, api+key, private+key, access+key, client+secret; word-split so "author"/"tokenizer" never match) holding a literal string of 6+ chars, and a secret-shaped literal (known prefix sk-/ghp_/github_pat_/xox*/AKIA/AIza/PEM, or 20+ chars across 3+ character classes) as a direct child of an "env" object. Already-references (${VAR}, ${env:VAR}, $VAR, env:VAR, %VAR%), placeholders, URLs, digit-only values and apiKeyHelper are never flagged. `secret-guard fix FILE...` is a dry run unless --apply; applying keeps a timestamped byte-exact backup, rewrites as clean JSON with ${VAR} references (${env:VAR} under .vscode/), and verifies the result re-scans clean. A secret's full value is NEVER printed — findings carry the key path and a fingerprint (first chars + length) only. Unparseable files are UNPARSEABLE findings, never crashes. Exit (scan) 0 = CLEAN, 1 = FINDINGS, 2 = error; (fix) 0 = nothing pending, 1 = pending or unfixable, 2 = error.
---

# secret-guard — agent skill

## Purpose

Agent and MCP configs are JSON files that ask for API
keys by name, so keys get pasted in literally — and then
committed. GitGuardian found 24,008 unique secrets in
public MCP configuration files in 2025, 2,117 of them
valid. Detection is a solved, crowded problem (gitleaks,
ggshield); remediation was the gap. secret-guard closes
it: it finds inline secrets in the config files agents
actually use and rewrites each one into the
environment-variable reference that file's client
already supports, printing the exact list of variables
to set.

**The safety core of this tool:** a secret's full value
is never printed — not in text output, not in `--json`,
not in error messages. Every report shows the key path
and a masked fingerprint (first characters + length).
This is enforced by the test suite, which runs a
distinctive planted secret through every mode and
asserts its absence from all output. `fix --apply` is
the only mode that writes, and it writes a timestamped
backup of the original bytes *before* the rewrite, then
verifies the rewritten file re-scans clean in memory
before the success is reported.

## When to use / not use

Use when:
- You (or an agent you direct) are about to commit,
  publish or share a config file: run `scan` first;
  if it reports findings, run `fix`, review the dry
  run, then `fix --apply`, and set the named variables
  in the environment.
- A pipeline adopts or ships agent tooling: the scan
  report is the config-secret half of the pre-publish
  check.
- You need a yes/no gate: exit 0 means none of the
  checked patterns were found; exit 1 hands you the
  exact list of key paths to move.

Do NOT use when:
- You want a general secret scanner for a whole repo.
  secret-guard checks two patterns in the JSON config
  files you name. It does not walk directories, scan
  source code, or read git history. Use gitleaks-class
  tools for the repo-wide sweep; use secret-guard for
  the config remediation they don't do.
- The config is TOML or YAML (e.g. a Codex
  `config.toml`). v0.1.0 parses the JSON family only
  and will report such a file UNPARSEABLE.
- You need the leaked secret *un-leaked*. Moving a
  value into an env var does nothing about copies in
  git history, chat logs or screenshots. Rotate the
  credential — secret-guard's reports say this every
  time, and so should you.

## Commands

```bash
# Report inline secrets in one or more config files
python3 src/secret_guard.py scan FILE [FILE ...]

# Same facts as one JSON object — for scripts and agents
python3 src/secret_guard.py scan FILE --json

# Show the rewrite without writing anything (exit 1
# while changes are pending)
python3 src/secret_guard.py fix FILE

# Apply it: backup first, rewrite, verify clean
python3 src/secret_guard.py fix FILE --apply
```

## Rules (exact)

- **`inline-secret`** (INLINE-SECRET) — a key whose
  word-split name (split on non-alphanumerics and
  camelCase boundaries, lowercased) contains one of the
  words `token`, `secret`, `password`, `passwd`, `auth`,
  `authorization`, `bearer`, `apikey`, or one of the
  adjacent pairs (`api`, `key`), (`private`, `key`),
  (`access`, `key`), (`client`, `secret`) — and whose
  value is a string that, stripped, is 6+ characters,
  not all digits, and not exempt (below). The key
  `apiKeyHelper` (any case) is carved out by exact name:
  its value is a shell command, never a secret.
- **`env-literal`** (ENV-LITERAL) — a string that is a
  *direct* child of a dict stored under a key named
  `env` (any case), whose key did not already match
  `inline-secret`, and whose stripped value is
  secret-shaped: it starts with a known prefix
  (`sk-ant-`, `sk-proj-`, `sk-`, `ghp_`, `gho_`, `ghu_`,
  `ghs_`, `ghr_`, `github_pat_`, `xoxb-`, `xoxa-`,
  `xoxp-`, `xoxr-`, `xoxs-`, `AKIA`, `AIza`,
  `-----BEGIN `) and is 10+ characters, OR it is 20+
  characters spanning 3+ of {lowercase, uppercase,
  digit, symbol}. Exempt and all-digit values are
  excluded here too.
- **`unparseable`** (UNPARSEABLE) — the file cannot be
  read as UTF-8, cannot be parsed even by the lenient
  parser, or its top level is not a JSON object.
  Exactly one finding per such file, with the reason in
  `detail`; its contents could not be checked.

Never flagged (the exemptions, applied before both
rules): empty or whitespace-only strings; environment
references — `${...}` (covers `${VAR}`, `${env:VAR}`,
`${VAR:-default}`), `$VAR`, `env:VAR`, `%VAR%`; obvious
placeholders — a fixed set (`your-key-here`,
`your_api_key`, `changeme`, `placeholder`, `example`,
`sample`, `dummy`, `fake`, `test`, `todo`, `none`,
`null`, `redacted`, `insert-here`, …), anything wrapped
in `<...>`, any single repeated character (`xxxx`,
`****`), anything starting with `your-`, `your_` or
`your `; and values starting with `http://` or
`https://` (endpoints, not secrets). Bare strings inside
arrays have no key and are never flagged. Values under
ordinary key names outside `env` blocks are never
checked.

Parsing: strict JSON first, then a string-aware JSONC
pass (`//` and `/* */` comments and trailing commas
stripped; a `//` inside a string — e.g. a URL — is
preserved). A UTF-8 BOM is tolerated.

Findings are reported per file, in document order.

## The fix (exact)

- Env var name: the key's words in `UPPER_SNAKE`
  (`apiKey` → `API_KEY`, `clientSecret` →
  `CLIENT_SECRET`); a name starting with a digit is
  prefixed `SECRET_`. Within one file, the same name
  for the *same* value (compared by hash, internally
  only) reuses one variable; the same name for a
  *different* value is disambiguated with the nearest
  ancestor segment (`BETA_API_KEY`), then a numeric
  suffix.
- Reference syntax: `${env:NAME}` when any component of
  the file's path is `.vscode` (VS Code's syntax);
  `${NAME}` otherwise.
- Dry run (no `--apply`): prints pending changes and
  the env-var list, writes nothing, creates no backup,
  exits 1 while anything is pending.
- `--apply`: the rewrite is built and re-scanned in
  memory first and must be CLEAN; then the backup
  `<file>.secret-guard-backup-YYYYMMDD-HHMMSS` (with a
  numeric suffix on collision) is written with the
  original bytes; then the file is written as
  indent-2 JSON with a trailing newline. Comments and
  original formatting are NOT preserved in the rewrite
  — only in the backup. Files with no findings are not
  touched and get no backup; re-running `--apply` on a
  fixed file is a no-op.

## Output JSON schema (`--json`)

Scan: `tool` (`"secret-guard"`), `version`, `command`
(`"scan"`), `files`, `summary`, `clean`. Each file
entry: `file`, `status` (`"ok"` | `"unparseable"`),
`findings`, `clean`. Each finding: `rule`
(`inline-secret` | `env-literal` | `unparseable`),
`verdict` (`INLINE-SECRET` | `ENV-LITERAL` |
`UNPARSEABLE`), `path` (dotted key path, list indices
as `[i]`; `null` for unparseable), `key`, `fingerprint`
(first characters + length, e.g. `gh…(27 chars)`;
`null` for unparseable), `env_var` (the name `fix`
will use; `null` for unparseable), `detail`.
`summary`: `{files, total, inline_secret, env_literal,
unparseable}`. `clean` is true exactly when there are
no findings.

Fix: `tool`, `version`, `command` (`"fix"`), `apply`
(bool), `files`, `env_vars`, `summary`, `clean`. Each
file entry: `file`, `status` (`clean` | `pending` |
`fixed` | `unparseable`), `changes`, `backup` (path or
`null`). Each change: `path`, `key`, `env_var`, `ref`
(the exact replacement string), `fingerprint`.
`env_vars`: `[{name, file, path}]` — every variable the
user must set, deduplicated per (name, file, path).
`summary`: `{files, changes, changed_files,
unparseable}`. `clean` is true when nothing is pending
and nothing is unparseable (after an `--apply`, when
every change was written and verified).

On error, stdout is a single object: `{"error":
"<message>"}` with exit code 2 — including argparse
usage errors in `--json` mode. Never plain text, never
a traceback. Input errors (a path that doesn't exist or
is a folder) abort the whole run before any file is
processed.

## Exit codes

Scan:
- `0` — CLEAN: no findings in any named file.
- `1` — FINDINGS: at least one finding of any verdict,
  including UNPARSEABLE. Nothing was written.
- `2` — ERROR: a path is missing or a folder, an
  invalid flag. No output facts may be quoted from a
  failed run.

Fix:
- `0` — nothing pending: every file was already clean,
  or `--apply` wrote and verified every change.
- `1` — changes are pending (dry run), or at least one
  file was UNPARSEABLE and could not be fixed.
- `2` — ERROR: as scan, plus a backup or rewrite that
  could not be written (the message names the backup
  holding the original bytes).

## Limits & honesty rules the agent must respect

- **CLEAN never means "safe".** It means: in the files
  named, no secret-named key holds a literal value and
  no `env` block holds a secret-shaped literal. Say
  exactly that. A secret under an ordinary key name
  outside an `env` block is outside the checked
  patterns and will not be reported.
- **Never quote a secret value.** The fingerprint
  (first characters + length) is the only shareable
  form. If a human pastes a full secret into the
  conversation, do not echo it back in your summary —
  refer to its key path and fingerprint.
- **A moved secret may still be a leaked secret.**
  Whenever you apply a fix to a file that was ever
  committed, pushed or shared, say plainly that the
  credential must be rotated: the fix stops future
  exposure from this file, it does not erase history.
- **UNPARSEABLE means unknown, not clean.** A config
  that could not be parsed could not be checked; treat
  it as unscanned until a human reads it. Do not report
  a run containing an UNPARSEABLE file as "all clear"
  even when every other file is clean.
- **The backup is the undo.** Before telling a user a
  fix is irreversible or hand-editing a rewritten file,
  point at the `.secret-guard-backup-*` file: copying
  it back over the config restores the original
  byte-for-byte.
- Local only: the tool reads only the files named on
  the command line, writes only backups and rewrites
  of those same files under `fix --apply`, and sends
  nothing anywhere.
