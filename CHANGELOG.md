# Changelog

## v0.1.0 — 2026-11-04

First release.

- **Find inline secrets in agent configs — and fix
  them.** Born from GitGuardian's State of Secrets
  Sprawl research: 24,008 unique secrets found in
  public MCP configuration files in 2025, 2,117 of
  them valid. Scanners list such keys; secret-guard
  does the remediation step they skip — rewriting each
  literal into the environment-variable reference the
  client already supports, and printing the exact list
  of variables to set.
- **Two rules, precision over recall** —
  `inline-secret`: a secret-named key (word-split on
  separators and camelCase, so `author` never matches
  `auth`: token, secret, password, passwd, auth,
  authorization, bearer, apikey, api+key, private+key,
  access+key, client+secret) holding a literal string
  of 6+ characters; `env-literal`: a secret-shaped
  value (known prefix — `sk-`, `ghp_`, `github_pat_`,
  `xox[baprs]-`, `AKIA`, `AIza`, PEM header — or 20+
  chars across 3+ character classes) as a direct child
  of an `env` object, whatever its key is named.
- **Never flagged** — values that are already
  environment references (`${VAR}`, `${env:VAR}`,
  `$VAR`, `env:VAR`, `%VAR%`), empty strings, obvious
  placeholders (`your-key-here`, `changeme`,
  `<paste-your-key>`, `xxxx`), URLs, all-digit values,
  and Claude Code's `apiKeyHelper`, whose value is a
  shell command. A finding is reported with its key
  path and a masked fingerprint (first characters +
  length) — **a secret's full value is never printed**,
  in any mode; the test suite proves it by running a
  distinctive planted secret through scan, fix,
  dry-run and `--json` output and asserting its
  absence.
- **`fix` with a safe round trip** — dry run by
  default (exit 1 while changes are pending, nothing
  written); `--apply` verifies the rewrite re-scans
  clean in memory, writes a timestamped backup of the
  original bytes beside the file, and only then
  writes. Reference syntax follows the ecosystem:
  `${env:VAR}` for files under `.vscode/`, `${VAR}`
  elsewhere; env names derive from the key
  (`apiKey` → `API_KEY`), disambiguated by ancestor on
  collision and reused when the same value repeats.
  Fixing a clean file writes nothing and makes no
  backup; a second `--apply` is a no-op. Rewrites are
  re-emitted as clean indent-2 JSON — comments and
  formatting survive only in the backup, and the
  README says so.
- **JSONC-tolerant parsing** — strict JSON first, then
  a string-aware pass that strips `//` / `/* */`
  comments and trailing commas (a `//` inside a URL
  string is data and survives). A checked file that
  still cannot be parsed — or is not a JSON object, or
  not UTF-8 — becomes an UNPARSEABLE finding ("could
  not be checked"), never a crash and never a silent
  skip. TOML/YAML configs are out of scope for v0.1.0
  and land in the same UNPARSEABLE bucket rather than
  being guessed at.
- **`--json` on both commands** — one JSON object with
  the same facts and exit codes as the text view
  (findings with file / path / key / fingerprint /
  env var; fix outcomes with changes, backup paths and
  the env-var list); errors are `{"error": ...}`
  objects, argparse usage errors included. Exit codes:
  scan 0 CLEAN · 1 FINDINGS · 2 ERROR; fix 0 nothing
  pending · 1 pending or unfixable · 2 ERROR.
- **`SKILL.md`** at the repo root for AI coding agents:
  the detection rules at their exact edges, the JSON
  schema, exit codes, and the honesty rules (CLEAN
  means "none of the checked patterns were found",
  never "this config is safe"; never quote a secret
  value — fingerprint only; a moved secret that was
  ever shared must still be rotated).
- Bundled sample generator (`examples/make_sample.py`):
  a leaky MCP config written as JSONC (3 findings
  worked out by hand: 2 INLINE-SECRET · 1 ENV-LITERAL,
  beside a URL, a low-entropy env value and an existing
  reference that must NOT be flagged), a VS Code
  `mcp.json` under `.vscode/` (1 finding; fix uses
  `${env:...}` syntax), and a clean config (env
  reference, placeholders, empty value, an `author`
  key) that must come back CLEAN. All planted secrets
  are invented FAKE strings.
- 57 stdlib-unittest tests, temp dirs only: both rules
  in both directions, every exemption pinned, the
  parser at its edges (comments in strings, block
  comments, trailing commas, BOM), the exact bundled-
  sample counts, malformed configs as findings, clean
  input errors with no tracebacks, the fix round trip
  (byte-identical backup, rescan clean, idempotent
  re-apply, collision and reuse of env names), and
  the never-print-a-secret proof across every mode.
- Pure Python standard library; local only; no network
  code; MIT licence.
