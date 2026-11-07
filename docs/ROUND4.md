# Round 4: the stranger's first hour

Scope: what someone gets from `pip install mcpdrift` and the README, not new detection features. Branch `expert-2`. Nothing was published, tagged, pushed or uploaded.

## How this review was run (honest)

The specialists below were **played by one agent in one session**. This run had no tool for starting independent sub-agents, so there was no second pair of eyes: every "finding" is something the same agent then ran, but the roles are not independent reviewers. A real second reviewer is still worth having. Each finding names the command that proved it. Commands were run from `/tmp/r4-mcpdrift/` scratch (a clean venv per Python version, a folder with a space in its name, and a non-root user for the read-only test). Python 3.11 and 3.13 were used for clean installs of the built wheel (3.12 only for `mcpdrift demo`); 3.9, 3.10, Windows and macOS were not run.

## Baseline (before any change)

| Measure | Result |
|---|---|
| `pytest -q` | 159 passed |
| `python bench/bench.py` | recorded; detection results unchanged at the end, only timings moved (0.54 to 0.66 s for 500-tool scan) |
| `ruff check .` (default rules from the machine's config) | 305 findings, mostly style; with the new project config (`E9,F,B,PLE`) 12, all fixed or ignored for test files that contain control characters on purpose |
| `mypy src` | 20 errors; 0 now |
| `twine check` on sdist and wheel | passed |
| Registry (`pip index versions mcpdrift`, read-only, 2026-11-07) | only `0.1.0` is published |

## Findings by specialist

### 1. First-time user (README only, clean venv)
- **README quick start failed after `pip install`.** It said `mcpdrift snapshot --from-file examples/notes-v1.json`, but the wheel has no `examples/` folder. Proof: `unzip -l dist/*.whl` listed no example files. Fixed: examples moved into the package, new `mcpdrift demo` runs them. Test: `test_demo_runs_from_the_installed_package`; verified from a wheel installed in a clean venv, run from a folder with a space.
- `pip install mcpdrift` gives **0.1.0**, which has none of what the README describes. Fixed with a version note in the README and the checklist.
- `mcpdrift` with no arguments prints an argparse error (exit 2). Left as is (standard, readable).

### 2. Release / packaging engineer
- `requires = ["setuptools>=68"]` with `license = "MIT"` (an SPDX string) only works with setuptools 77 or newer. It built here only because pip fetched the newest. Fixed: `>=77`.
- Version lived in two places (`pyproject.toml`, `__init__.py`). Fixed: `dynamic = ["version"]` reading `mcpdrift.__version__`; `test_version_is_one_number_everywhere` also requires a CHANGELOG heading for it.
- Missing: `py.typed`, project URLs, Python classifiers, a real author name, `license-files`, sdist contents (no CHANGELOG, bench, examples). Fixed (`MANIFEST.in`; checked with `tar tzf` and `unzip -l`).
- `python -m build` then `twine check`: both pass. Wheel lists 20 files, no tests, no secrets, no local paths (`strings | grep` for home paths and token-like text found nothing).
- Next release number: see PUBLISH-CHECKLIST.md.

### 3. Supply-chain security reviewer
- **Fail-open listing (the main bug of the round).** If a server timed out, closed its pipe, sent an oversized message, or (HTTP) answered 500 on `tools/list`, the code returned an empty list. `snapshot` then pinned zero tools; `check --fail-on high` passed a "removed tool" (medium) as fine. Proof: a fake server that sleeps on `tools/list`, `mcpdrift check --timeout 2` took 29 s and printed `MEDIUM removed tools.t`. Fixed: only JSON-RPC "method not found", or an error for a capability the server did not advertise, means "empty". Tests: `test_failed_tools_listing_is_an_error_not_an_empty_surface` (hang, exit, JSON-RPC error), `test_check_does_not_report_removed_tool_when_server_hangs`, `test_http_error_on_tools_listing_is_an_error`, `test_http_404_for_a_section_the_server_never_advertised_is_empty`.
- A lock with an unknown newer `lockfile_version` was compared as if understood (`lockfile_version: 99` printed "no drift"). Fixed: refused with exit 2.
- Windows only (static): `shutil.which("ssh-keygen")` searches the working folder first there, so a repository with its own `ssh-keygen.exe` could fake a good signature. Fixed with `_exe.find_exe` (never searches the current folder) and an absolute `taskkill.exe`. Unit-tested on Linux with a simulated Windows search; never run on Windows.
- Reviewed and found fine: GitHub Action passes inputs through env vars, workflow-command output is wrapped in `::stop-commands::`, `--allow-env` gating for header expansion, no `shell=True` anywhere (`grep -rn shell src`).
- Not changed: the Action's own `actions/checkout@v4` and `setup-python@v5` are tag-pinned, not SHA-pinned.

### 4. Docs / DX writer
- A literal zero-width space inside the README sentence that explains zero-width escapes (renders as nothing). Fixed, plus `test_docs_have_no_invisible_characters`.
- Every command inside README code fences is checked against the real sub-commands (`test_readme_quick_start_commands_are_real_subcommands`).
- Exit codes now documented with the new ones (a stalled server is 2, interrupt is 130).
- Competitor table re-checked on PyPI today: `mcp-scan` is now a redirect to `snyk-agent-scan`; `mcp-pin` and `heldfast` have the same description (0.1.8 and 0.2.3); `mcp-warden-cli` 2.2.0 needs Python 3.11+. A "Minimum Python" row was added from each project's `requires_python`.

### 5. CI/CD integrator
- Bad config / unknown `--server` / no source exited **1**, the code CI reads as "drift", instead of 2. Proof: `echo '{' > bad.json; mcpdrift snapshot --config bad.json; echo $?` printed 1. Fixed, with tests.
- `check` required `--lock`; now defaults to `mcp.lock.json` (backward compatible).
- A config whose single server was renamed made `check` fail even though the lock was fine. Fixed (`test_renamed_single_server_still_checks_against_lock`); an explicit `--server` that does not exist is still an error.
- CI file: added ruff, a Windows job and a macOS job (both allowed to fail until seen passing), and a job that builds the wheel, installs it in a clean venv and runs `mcpdrift demo`. **Not run on any CI service** from here.

### 6. Hostile-input fuzzer
- 4,500 random listings (junk types, lone surrogates, 5,000-char strings, control and bidi characters, nested structures) through `scan`, `snapshot` and `check --format sarif` in process: exit codes only 0, 1 or 2, zero "internal error" messages (`/tmp/r4-mcpdrift/fuzz.py`, seeded; not committed).
- 20,000 tools (2.6 MB): snapshot 5.3 s, check 2.0 s.
- Terminal escapes and bidi characters in tool names are shown as `\u001b`-style escapes (`mcpdrift scan --lock esc.lock | cat -v`).
- Ctrl-C was not caught anywhere (Python would print a traceback); now exit 130 with one line, tested by raising `KeyboardInterrupt` in a command.
- Importing `mcpdrift.__main__` ran the CLI; now guarded.

### 7. Performance engineer
- Bench rerun after the changes: all detection results identical to baseline (58 values compared); timing differences are within noise. Nothing slower was introduced: the listing change adds no extra round trips.
- Unchanged and noted: the default `--samples 3` triples listing round-trips.

### 8. Competitor's maintainer (read-only, PyPI pages only)
- What a rival would say: "mcpdrift cannot block at runtime" (true, documented), "SSH-signed locks are less standard than Sigstore" (a trade-off, documented), "no Windows testing" (true, now said in the README and CI). Their strongest published points are runtime `guard`/`gateway` modes and output-schema/annotation pinning in `mcp-warden-cli` 2.x. mcpdrift already stores whole tool objects, so annotations and `outputSchema` are pinned too; this was not re-tested against that project. Feature claims about their products come from their PyPI descriptions only; nothing was run.

## Windows static review (not run on Windows)

| Area | Finding | Action |
|---|---|---|
| Path separators | SARIF URI turned any absolute path into a bare file name; Windows paths were handled via `replace("\\", "/")` | now relative to the working folder when inside it; test added |
| `os.replace` on an open file | fails with `PermissionError` while an editor or scanner holds the target | retry up to 6 times on Windows, then a plain error |
| Console encoding | already `backslashreplace` on stdout/stderr | none |
| Colour | legacy console shows raw escape codes | off on Windows unless `WT_SESSION`, `ANSICON`, `ConEmuANSI`, `TERM_PROGRAM` or `COLORTERM` is set |
| CRLF | locks and signatures are read with universal newlines and hashed as parsed JSON, so CRLF checkouts verify | tested on Linux with a CRLF copy and a BOM copy |
| `shell=True` | none | none |
| Signals | `killpg`, `waitid`, `start_new_session` are POSIX-only and guarded | on Windows the tree is stopped with `taskkill /T /F` (new, untested) |
| Helper programs | working folder searched first | see supply-chain section |

## Idea list (scored)

Scale: value and differentiation 1 (low) to 5 (high); effort S/M/L; risk to existing users L/M/H.

| # | Idea | Value | Diff. | Effort | Risk | Status |
|---|---|---|---|---|---|---|
| 1 | Listing failure is an error, never "empty" | 5 | 4 | S | L | DONE |
| 2 | Config/usage errors exit 2, not 1 | 5 | 2 | S | L | DONE |
| 3 | `mcpdrift demo` that works after `pip install` | 5 | 3 | S | L | DONE |
| 4 | Ship example listings and `py.typed` in the wheel | 4 | 1 | S | L | DONE |
| 5 | Complete package metadata (URLs, classifiers, author) | 3 | 1 | S | L | DONE |
| 6 | Single version source plus a consistency test | 3 | 1 | S | L | DONE |
| 7 | `setuptools>=77` for the SPDX license field | 4 | 1 | S | L | DONE |
| 8 | sdist carries CHANGELOG, tests, bench, examples | 3 | 1 | S | L | DONE |
| 9 | Refuse locks from a newer lockfile version | 4 | 3 | S | L | DONE |
| 10 | `--lock` defaults to `mcp.lock.json` | 3 | 1 | S | L | DONE |
| 11 | Renamed single server still checks | 3 | 1 | S | L | DONE |
| 12 | Plain-English write errors, retry on Windows | 3 | 1 | S | L | DONE |
| 13 | Windows: tree kill, colour, find helpers outside the working folder | 4 | 2 | M | M | DONE (untested on Windows) |
| 14 | Relative SARIF paths | 3 | 2 | S | L | DONE |
| 15 | Ctrl-C exit 130, no traceback | 2 | 1 | S | L | DONE |
| 16 | ruff and mypy clean, ruff in CI | 3 | 1 | M | L | DONE |
| 17 | CI: Windows/macOS jobs and a clean-wheel smoke job | 4 | 2 | S | L | DONE (never run) |
| 18 | README honesty: version note, limits, refreshed competitors | 4 | 3 | S | L | DONE |
| 19 | Tests that police docs (invisible characters, real sub-commands) | 3 | 2 | S | L | DONE |
| 20 | Real Windows/macOS/3.9 test runs | 5 | 1 | M | L | NOT-DONE (needs those machines) |
| 21 | Legacy HTTP+SSE transport | 3 | 3 | L | M | NOT-DONE (use `--from-file`) |
| 22 | Auto-discover `.mcp.json` in the current folder | 3 | 2 | S | H | NOT-DONE on purpose: it would launch a command from a fork's checkout without being asked |
| 23 | `check --all` for every server in a config | 4 | 3 | M | M | NOT-DONE |
| 24 | Trusted-publishing release workflow on tag | 4 | 2 | M | M | NOT-DONE (publishing was off limits; see checklist) |
| 25 | SHA-pinned actions in the repo's own workflows | 3 | 2 | S | L | NOT-DONE (needs a lookup of current commit hashes) |
| 26 | JUnit XML output | 2 | 2 | S | L | NOT-DONE |
| 27 | Output-schema / annotation drift tests against mcp-warden fixtures | 3 | 3 | M | L | NOT-DONE |
| 28 | Locking the seq across simultaneous snapshots | 2 | 1 | M | L | NOT-DONE (documented limit) |

## What could not be tested

- Windows, macOS, Python 3.9 and 3.10 (only 3.11, 3.12 for the demo, and 3.13 ran).
- The GitHub Action and the CI file end to end; no CI service was used.
- A real remote MCP server over HTTPS, real `npx` servers, or a passphrase-protected signing key.
- `uvx`/`pipx` installs (not tried).
- Anything on the registry beyond reading version numbers and descriptions; no upload was attempted.
