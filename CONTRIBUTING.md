# Contributing

Contributions are welcome — bug reports, fixes and small focused features.

## Ground rules

- **Standard library only.** secret-guard's promise is
  "clone and run". Pull requests that add a third-party
  dependency will not be merged.
- **Local only.** No network calls, no telemetry, no
  uploads of user files. The tool reads the config
  files named on the command line and sends nothing
  anywhere.
- **A secret value is never printed — never weaken
  this.** No output path (text, `--json`, errors,
  debug aids) may include a finding's value; key paths
  and fingerprints (first characters + length) are the
  only shareable forms. A PR that logs "the value being
  replaced" for convenience will not be merged — the
  suite plants a distinctive secret and greps every
  mode's output for it; keep those tests green.
- **`scan` writes nothing; `fix` writes carefully.**
  A dry run must not touch the disk, backups included.
  An `--apply` must verify the rewrite re-scans clean
  in memory, write the byte-exact backup *before* the
  rewrite, and leave clean files completely untouched
  (no rewrite, no backup). A PR that writes first and
  checks later, or backs up after rewriting, will not
  be merged.
- **Precision is the product.** The flagged set is two
  patterns: secret-named keys holding literals, and
  secret-shaped literals in `env` blocks. Ordinary
  values — URLs, placeholders, references, digit IDs,
  prose — are never findings. A PR that widens
  detection needs a false-positive analysis against
  realistic configs, not just a true-positive demo:
  every exemption in the test suite exists because a
  real config shape needed it.
- **Unparseable is a finding, never a crash and never
  a skip.** Any new parser path or file shape must
  route its failures to the UNPARSEABLE finding. A
  traceback in a scan or a fix is a release-blocking
  bug.
- **Both directions tested.** A behaviour change needs
  a test where the pattern fires and one where it does
  not (a placeholder, a reference, a hook-free clean
  config) — not just one side. Expected findings need
  hand-computed values (paths, fingerprints, env
  names), not output copied from the tool itself.

## Getting started

```bash
git clone https://github.com/jasveerai88/secret-guard
cd secret-guard
python3 -m unittest discover -s tests -v
python3 examples/make_sample.py /tmp/secret-guard-demo
python3 src/secret_guard.py scan /tmp/secret-guard-demo/mcp-config.json
python3 src/secret_guard.py fix /tmp/secret-guard-demo/mcp-config.json
```

## Pull requests

1. Fork, branch, and keep the change to one topic.
2. Add or update tests under `tests/`; the full suite must pass.
3. Note the change in `CHANGELOG.md` under an "Unreleased" heading.
4. Describe the behaviour change with a real before/after run if
   the CLI output changes — with fingerprints only, never a
   real or realistic-looking secret value.
