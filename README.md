# secret-guard

**Scanners find the API key you pasted into your MCP
config. secret-guard removes it.**

GitGuardian's *State of Secrets Sprawl* research found
**24,008 unique secrets in public MCP configuration files
in 2025 — 2,117 of them valid**. The configs AI agents
actually run on — `.mcp.json`, Claude Code settings,
VS Code `mcp.json`, Cursor-style configs — are JSON files
full of `env` blocks, and the path of least resistance is
pasting the key in literally. Detection tools (gitleaks,
ggshield) will happily list those keys for you. Almost
nothing does the boring, useful next step: **rewriting
each literal into the environment-variable reference the
client already supports**, and telling you exactly which
variables to set.

That rewrite is secret-guard's whole job.

- `scan` reports every inline secret — by key path and
  masked fingerprint, **never by value**
- `fix` rewrites them to `${VAR}` references (or
  `${env:VAR}` in VS Code configs), dry-run by default;
  `--apply` writes only after keeping a timestamped
  backup of the original bytes, and verifies the
  rewritten file re-scans clean before reporting success
- Pure Python 3 standard library — no dependencies, no install step
- Local only — your files never leave your machine, and
  no secret value is ever printed, in any mode

## The rules

Two rules, deliberately narrow. A scanner that cries
wolf on ordinary values gets ignored, and then it
protects nobody — so this is precision over recall.

| Rule | Where | What counts |
|---|---|---|
| `inline-secret` | any key, anywhere in the file | The key's name contains a secret word — `token`, `secret`, `password`, `passwd`, `auth`, `authorization`, `bearer`, `apikey`, or the pairs `api`+`key`, `private`+`key`, `access`+`key`, `client`+`secret` — and its value is a literal string of 6+ characters. Key names are word-split on separators and camelCase, so `author` does not match `auth` and `tokenizer` does not match `token`. |
| `env-literal` | direct string children of any object under a key named `env` | The value is secret-shaped whatever the key is called: a known secret prefix (`sk-`, `ghp_`, `github_pat_`, `xox[baprs]-`, `AKIA`, `AIza`, a PEM header) at 10+ chars, or high entropy — 20+ chars spanning 3+ character classes (lower / upper / digit / symbol). |
| `unparseable` | any scanned file | The file can't be parsed as JSON (comments tolerated), isn't UTF-8, or its top level isn't a JSON object. It could not be checked — reported, never silently skipped, never a crash. |

**Never flagged:** values that are already environment
references (`${VAR}`, `${env:VAR}`, `$VAR`, `env:VAR`,
`%VAR%`), empty strings, obvious placeholders
(`your-key-here`, `changeme`, `<paste-your-key>`,
`xxxxxx`), URLs (endpoints, not secrets), all-digit
values (IDs, not secrets), and Claude Code's
`apiKeyHelper` — its value is a shell command, not a
secret. Values under ordinary key names outside `env`
blocks are not checked at all.

Config files in the wild are JSON-with-comments, so
parsing is lenient: `//` and `/* */` comments and
trailing commas are tolerated, string-aware (a `//`
inside a URL in a string is data, not a comment).

## What `fix` does, exactly

1. Computes the same findings as `scan`, and the env var
   name for each: the key name in `UPPER_SNAKE` form
   (`apiKey` → `API_KEY`). If two *different* secrets in
   one file would take the same name, the later one is
   prefixed with its nearest ancestor (`BETA_API_KEY`);
   the *same* secret value under the same name reuses one
   variable.
2. Dry run (default): prints each pending change and the
   list of environment variables to set. Writes nothing,
   makes no backups.
3. `--apply`: builds the rewritten file in memory,
   re-scans it and requires CLEAN, then writes a
   timestamped backup (`<file>.secret-guard-backup-
   YYYYMMDD-HHMMSS`, the original bytes exactly) beside
   the original, and only then writes the rewrite.
4. The rewrite is clean JSON, indent 2. **Comments and
   original formatting are not preserved** — the backup
   is where they live. Fixing a file with no findings
   changes nothing and creates no backup, and a second
   `fix --apply` is a no-op.

Reference syntax follows the file's ecosystem: files
under a `.vscode/` folder get VS Code's `${env:VAR}`;
everything else gets `${VAR}`.

## Usage

```bash
# 0. Build the bundled samples (or use your own configs)
python3 examples/make_sample.py /tmp/secret-guard-demo

# 1. Scan — writes nothing
python3 src/secret_guard.py scan CONFIG...

# 2. See what a fix would do (dry run), then apply it
python3 src/secret_guard.py fix CONFIG
python3 src/secret_guard.py fix CONFIG --apply

# 3. Drive it from a script or an agent
python3 src/secret_guard.py scan CONFIG --json
python3 src/secret_guard.py fix CONFIG --apply --json
```

Exit codes — `scan`: `0` = CLEAN, `1` = FINDINGS,
`2` = error. `fix`: `0` = nothing pending (already
clean, or `--apply` wrote and verified every change),
`1` = changes pending (dry run) or a file could not be
fixed (unparseable), `2` = error.

## Use with AI agents

Every run takes `--json`: one JSON object with the same
facts and exit codes as the text view (errors come back
as `{"error": ...}`, argparse usage errors included).

Agents: read [SKILL.md](SKILL.md) first — the detection
rules at their exact edges, the JSON schema, exit codes,
and the honesty rules (CLEAN means "none of the checked
patterns were found", never "this config is safe";
fingerprints are the only form in which a secret may be
quoted; a moved secret that was ever shared must still
be rotated).

The workflow this enables: before an agent commits,
publishes or shares any config file, it runs
secret-guard; if there are findings it applies the fix,
sets the named variables in the environment, and the
config that lands in git contains references, not keys.

## Real runs (verbatim)

Building the bundled samples — one leaky MCP config, one
VS Code config, one clean config — and scanning:

```text
$ python3 examples/make_sample.py /tmp/secret-guard-demo
Created /tmp/secret-guard-demo/mcp-config.json, /tmp/secret-guard-demo/.vscode/mcp.json and /tmp/secret-guard-demo/clean-config.json
(exit code: 0)

$ python3 src/secret_guard.py scan /tmp/secret-guard-demo/mcp-config.json
secret-guard v0.1.0 — scan · 1 file(s)
3 finding(s) — 2 INLINE-SECRET · 1 ENV-LITERAL · 0 UNPARSEABLE

INLINE-SECRET — a literal secret stored under a secret-named key (2):
  /tmp/secret-guard-demo/mcp-config.json — mcpServers.github.env.GITHUB_TOKEN
    key "GITHUB_TOKEN" holds a literal secret: gh…(27 chars). Fix rewrites it as the GITHUB_TOKEN environment variable.
  /tmp/secret-guard-demo/mcp-config.json — apiKey
    key "apiKey" holds a literal secret: sk…(24 chars). Fix rewrites it as the API_KEY environment variable.

ENV-LITERAL — a secret-shaped literal in an env block, whatever the key is named (1):
  /tmp/secret-guard-demo/mcp-config.json — mcpServers.weather.env.SERVICE_KEY
    key "SERVICE_KEY" holds a literal secret: Q7…(24 chars). Fix rewrites it as the SERVICE_KEY environment variable.

VERDICT: FINDINGS — move each value into the named environment variable (run the fix command to rewrite the files), and rotate any secret that was ever committed or shared: moving it does not un-leak it.
secret-guard never prints a secret's value: reports show the key path and a fingerprint (first characters + length) only.
(exit code: 1)
```

Note what is *not* in the report: the sample's
`GITHUB_HOST` (a URL), its `UNITS` env value (short, low
entropy), and its `NOTES_API_KEY` (already a `${...}`
reference). Ordinary values are not findings.

The clean sample:

```text
$ python3 src/secret_guard.py scan /tmp/secret-guard-demo/clean-config.json
secret-guard v0.1.0 — scan · 1 file(s)
0 finding(s) — 0 INLINE-SECRET · 0 ENV-LITERAL · 0 UNPARSEABLE

CLEAN — none of the patterns secret-guard checks were found: no secret-named key holds a literal value, and no env block holds a secret-shaped literal.
CLEAN never means "this config is safe". Values under ordinary key names outside env blocks are not checked, TOML/YAML configs are not parsed, and a secret that was ever committed or shared stays leaked even after it is moved — rotate it.
(exit code: 0)
```

Fixing a copy of the leaky sample — dry run first, then
for real:

```text
$ cp /tmp/secret-guard-demo/mcp-config.json /tmp/secret-guard-demo/fix-me.json
$ python3 src/secret_guard.py fix /tmp/secret-guard-demo/fix-me.json
secret-guard v0.1.0 — fix · DRY RUN — nothing written · 1 file(s)

/tmp/secret-guard-demo/fix-me.json — 3 change(s) pending:
  mcpServers.github.env.GITHUB_TOKEN → ${GITHUB_TOKEN}  (was gh…(27 chars))
  mcpServers.weather.env.SERVICE_KEY → ${SERVICE_KEY}  (was Q7…(24 chars))
  apiKey → ${API_KEY}  (was sk…(24 chars))

Environment variables to set — the values are the ones currently in the files; secret-guard never prints them:
  GITHUB_TOKEN  ← /tmp/secret-guard-demo/fix-me.json · mcpServers.github.env.GITHUB_TOKEN
  SERVICE_KEY  ← /tmp/secret-guard-demo/fix-me.json · mcpServers.weather.env.SERVICE_KEY
  API_KEY  ← /tmp/secret-guard-demo/fix-me.json · apiKey

DRY RUN — nothing was written and no backups were made. Re-run with --apply to rewrite; a timestamped backup of each changed file is kept beside it first.
(exit code: 1)

$ python3 src/secret_guard.py fix /tmp/secret-guard-demo/fix-me.json --apply
secret-guard v0.1.0 — fix · APPLIED · 1 file(s)

/tmp/secret-guard-demo/fix-me.json — 3 change(s) written:
  mcpServers.github.env.GITHUB_TOKEN → ${GITHUB_TOKEN}  (was gh…(27 chars))
  mcpServers.weather.env.SERVICE_KEY → ${SERVICE_KEY}  (was Q7…(24 chars))
  apiKey → ${API_KEY}  (was sk…(24 chars))
  backup: /tmp/secret-guard-demo/fix-me.json.secret-guard-backup-20261104-043918
  verified: the rewritten file re-scans clean

Environment variables to set — the values are the ones currently in the files; secret-guard never prints them:
  GITHUB_TOKEN  ← /tmp/secret-guard-demo/fix-me.json · mcpServers.github.env.GITHUB_TOKEN
  SERVICE_KEY  ← /tmp/secret-guard-demo/fix-me.json · mcpServers.weather.env.SERVICE_KEY
  API_KEY  ← /tmp/secret-guard-demo/fix-me.json · apiKey

Applied and verified. Set the environment variables above, then restart the client that reads these configs. Rotate any secret that was ever committed or shared.
(exit code: 0)

$ python3 src/secret_guard.py scan /tmp/secret-guard-demo/fix-me.json
secret-guard v0.1.0 — scan · 1 file(s)
0 finding(s) — 0 INLINE-SECRET · 0 ENV-LITERAL · 0 UNPARSEABLE

CLEAN — none of the patterns secret-guard checks were found: no secret-named key holds a literal value, and no env block holds a secret-shaped literal.
CLEAN never means "this config is safe". Values under ordinary key names outside env blocks are not checked, TOML/YAML configs are not parsed, and a secret that was ever committed or shared stays leaked even after it is moved — rotate it.
(exit code: 0)
```

(The backup's timestamp is from the run shown; yours
will differ. The backup holds the pre-fix file
byte-for-byte — comments included — so the rewrite is
always reversible by copying it back.)

And a config file that cannot be parsed at all. It is a
finding — the file could not be checked — not a crash:

```text
$ printf '{ "api_key": [ this is not json at all' > /tmp/secret-guard-broken.json
$ python3 src/secret_guard.py scan /tmp/secret-guard-broken.json
secret-guard v0.1.0 — scan · 1 file(s)
1 finding(s) — 0 INLINE-SECRET · 0 ENV-LITERAL · 1 UNPARSEABLE

UNPARSEABLE — could not be parsed, so its contents could not be checked (1):
  /tmp/secret-guard-broken.json — could not be parsed as JSON: Expecting value: line 1 column 16 (char 15)

VERDICT: UNPARSEABLE — the file(s) above could not be parsed, so their contents could not be checked or cleared. Read them by hand.
secret-guard never prints a secret's value: reports show the key path and a fingerprint (first characters + length) only.
(exit code: 1)
```

## Tests

```bash
python3 -m unittest discover -s tests -v
# Ran 57 tests — OK
```

The suite covers both directions: both rules fire on
their planted surfaces with hand-computed paths,
fingerprints and env names; every exemption is pinned
(env-reference forms, placeholders, URLs, digit-only
values, `author`, `tokenizer`, `apiKeyHelper`); the
lenient parser is pinned at its edges (`//` inside a URL
string is data, block comments, trailing commas, BOM);
malformed files, non-object roots and invalid UTF-8 are
UNPARSEABLE findings, never tracebacks; input errors are
exit 2 with `{"error": ...}` in `--json` mode, argparse
errors included. The fix is proven as a round trip —
dry run writes nothing, `--apply` leaves a byte-identical
backup and a file that re-scans CLEAN, a second `--apply`
is a no-op — and the core promise is tested directly: a
fixture with a distinctive planted secret is run through
every mode (scan text and JSON, fix dry-run text and
JSON, fix `--apply` text and JSON, rescan) and the full
secret string is asserted absent from every byte of
output, while its fingerprint is present.

## Two jobs this tool does

1. **For any developer using AI coding agents** (the
   public GitHub Sponsors surface): agent configs are
   the files most likely to be committed with live keys
   in them, because every client asks for the key in a
   JSON file. secret-guard turns "audit my configs and
   fix them" into one deterministic command a human or
   an agent can run before every commit or publish.
2. **For its author** (internal): the author's engine
   runs MCP and agent configs across many projects, and
   publishes tools publicly. secret-guard runs against
   the engine's own config surfaces before anything is
   shared or published, so a config that leaves this
   machine carries references, not credentials.

## Known limits

- **Two patterns only.** A secret stored under an
  ordinary key name outside an `env` block (say, a
  top-level `"sessionId"` holding a live token) is not
  checked in v0.1.0. That is the precision bargain —
  widening the net to every string in the file is how
  scanners train people to ignore them.
- **JSON family only.** `.codex/config.toml` and YAML
  configs are not parsed in v0.1.0; pointing secret-
  guard at one reports it UNPARSEABLE rather than
  guessing.
- **Rewrites normalize formatting.** `fix --apply`
  re-emits the whole file as indent-2 JSON; comments
  and layout are preserved only in the backup. If the
  comments matter day-to-day, copy them back from the
  backup after fixing.
- **No git history.** secret-guard checks the files you
  name, as they are now. A secret that was committed
  earlier is still in the repo's history — moving it out
  of the working file does not un-leak it. Rotate the
  credential; history rewriting is a separate job.
- **One reference syntax per ecosystem.** VS Code's
  `${env:VAR}` is chosen by the file living under a
  `.vscode/` folder; other clients get `${VAR}`. A
  client with a different syntax (or none) needs its
  references adjusted by hand.

## Privacy

What it touches: only the config files you name.
`scan` and dry-run `fix` write nothing. `fix --apply`
writes exactly two things per changed file: a backup
of the original beside it, and the rewritten file.
What it sends: nothing — there is no network code in
this tool. And it prints no secret values, ever.

## Support

If this catches one live key before it lands in a public
repo, consider sponsoring: **https://github.com/sponsors/jasveerai88**

## Licence

MIT — see [LICENSE](LICENSE).
