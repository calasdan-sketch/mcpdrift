# Changelog

## 0.3.0 (unreleased)

### Round 4: what a stranger gets from `pip install`
- **`mcpdrift demo`**: the 10-second example now ships inside the package. Before, the README quick start pointed at `examples/*.json`, which the wheel never contained, so it failed after `pip install`. `demo --dir DIR` keeps the files.
- **A listing that fails is an error, not "no tools".** A server that timed out, closed its pipe, sent an oversized message, or (over HTTP) answered 500 on `tools/list` used to be recorded as an empty section: `snapshot` would pin zero tools and `check` reported a "removed tool" (medium) that `--fail-on high` let through. Now only a JSON-RPC "method not found" (or any JSON-RPC error for a capability the server never advertised) means "empty". Everything else exits 2 and writes nothing.
- **Exit codes**: a missing or invalid config, an unknown `--server`, or no `--config`/`--from-file` used to exit `1` (the code for drift). They exit `2` now. Ctrl-C exits `130`.
- A lock whose `lockfile_version` is newer than this build understands is refused (exit 2, "upgrade mcpdrift") instead of being compared as if it were understood.
- `check` and `update` default `--lock` to `mcp.lock.json`. A config with a single server still works after the server is renamed.
- Writing a lock/report to a missing folder or read-only location gives one plain sentence (before: a temp-file name). `os.replace` is retried briefly on Windows, where an editor or scanner can hold the target.
- Windows (reviewed statically, **not run**): the whole process tree is stopped with `taskkill /T`; colour is off unless the console is known to understand it; SARIF paths are relative to the working folder.
- Packaging: `py.typed`, `Typing :: Typed`, Python 3.9 to 3.13 classifiers, project URLs, a real author, `license-files`, a sdist that carries CHANGELOG, tests, bench and the example listings, `setuptools>=77` (the SPDX `license = "MIT"` string needs it), and one version number (`mcpdrift.__version__`; `pyproject.toml` reads it).
- Housekeeping: ruff (`E9,F,B,PLE`) and mypy are clean and ruff runs in CI; CI also builds the wheel, installs it into a clean venv and runs `mcpdrift demo`, and has Windows and macOS jobs that may fail until someone has seen them pass. A literal zero-width space in the README is now written as an escape, and tests keep invisible characters out of the docs.
- README: version note (PyPI has 0.1.0), competitor versions re-checked on 2026-11-07 (mcp-scan is now a redirect to snyk-agent-scan), honest Windows and Python-version limits.

### Round 3 additions
- **Pinned now**: server `instructions`, `serverInfo` title/description/websiteUrl, the negotiated `protocolVersion`, and `resources/templates/list` (resource templates). All are risk-scanned like descriptions; `scan` covers them too. Fields are stored only when the server sends them.
- `mcpdrift diff OLD NEW` compares two lockfiles with no server involved; `python -m mcpdrift` works.
- `--isolate-env` / Action `isolate-env`: a stdio server gets a minimal environment, not the CI job's secrets.
- A server's `ping` gets an answer and its other requests get a "not supported" error (before, a server that waited on us made the listing time out). The server's process group is killed on exit, so `npx` children are not orphaned.
- Context-footprint finding when model-visible text grows a lot; `snapshot` prints the footprint.
- Wider text signals (more injection verbs and chat-template tokens, six languages, more credential locations, secret environment variables, markdown-image leaks), checked against benign phrases in tests.
- A bad listing now exits 2 with a one-line message instead of a traceback: listings nested over 400 levels are refused, and unexpected internal errors exit 2.

### Fixed in round 3
- `scan` and `check` were quadratic in the number of tools (500 tools took about 9 s; a hostile server may list 50,000). Cross-tool name matching is now a token lookup.
- `required` or `enum` lists containing objects or lists crashed the scorer with `TypeError`.
- Two regular expressions backtracked badly on 200,000-character text (`<` followed by spaces; newlines followed by `system`).

### Compatibility (round 3)
- First `check` against a lock from an earlier build reports `server.instructions` (medium) and resource templates (low) as added when the server has them; added title, description, websiteUrl and protocolVersion are `info`. Re-snapshot after reviewing.

### Added
- **Streamable HTTP servers** (`url` + `headers` in the config), JSON or event-stream responses, sessions, pagination. Plain http only to loopback, no redirects, URL credentials refused, `${VAR}` in headers only for `--allow-env` names.
- **Semantic normalization**: reordered `required`, `enum`, `type` unions and `anyOf`/`oneOf`/`allOf`, and ASCII whitespace-only changes in descriptions, are no longer drift. The lock still stores the raw surface; `--strict` restores exact comparison. Non-ASCII characters are never normalized.
- **Multi-sample listing** (`--samples`, default 3): a server that answers differently on later listings is reported as `unstable.*` (high or worse, with full text analysis); `snapshot`/`update` refuse to pin it unless `--allow-unstable`. `list_changed` notifications become a `low` finding.
- **`mcpdrift update`** with a review token bound to the exact drift; auto-accepts only `info` changes; records approvals in `history`; no rewrite when nothing changed.
- **SARIF 2.1.0** (`--format sarif`, `--sarif-out`), Action inputs `sarif-file`, `samples`, `strict`, and a `.pre-commit-hooks.yaml`.
- `bench/bench.py` reproducible benchmark.

### Changed
- `check` JSON output gains `review_token` and `cosmetic_ignored`. `--json` (legacy) is unchanged and compares raw.
- A config entry with a `url` is now fetched over HTTP instead of failing; `"type": "sse"` still errors, with a clearer message.
- Default listing count is 3 instead of 1, so a check makes two extra round-trips per section.

## 0.2.0 (unreleased)

### Added
- **Severity-graded findings** (`info` / `low` / `medium` / `high` / `critical`), each with reasons and tags (`breaking`, `widened`, `security`, `text`). `check --fail-on LEVEL` gates CI on severity.
- **Rug-pull text analysis** of changed descriptions and titles at any depth. It looks for invisible, bidi, tag and variation-selector characters, mixed-script look-alikes, hidden-instruction markers, secret-file paths, exfiltration wording, new URLs and cross-tool references. Only *new* signals count, and several strong signals together escalate to `critical`.
- **Schema-aware classification**: new required argument, removed argument, type change, enum narrowed/widened, `additionalProperties: false`, constraint changes, and annotation flips (`destructiveHint`, `readOnlyHint`, `openWorldHint`).
- **`mcpdrift scan`** risk-scans a lock or live server with no baseline, because pinning can't catch a server that was poisoned before you pinned it. `snapshot` warns when it pins a risky surface.
- **Readable output**: word-level diffs with invisible characters escaped. `--format text|json|markdown|github`, and `--markdown-out` for `$GITHUB_STEP_SUMMARY`.
- **Signed lockfiles**: `snapshot --sign-key`, `sign`, `verify`, and `check --allowed-signers/--identity`, built on `ssh-keygen -Y` with no new dependency.
- **Lockfile v2** with per-tool and whole-surface SHA-256 digests. A hand-edited surface fails with exit code `3`.
- **`--from-file`** checks a saved `tools/list` response without executing anything.
- **`--ignore-file`** (globs, `#` comments) and `--protocol-version`.
- **GitHub Action** (`action.yml`): annotations, job summary and an `exit-code` output. It installs from its own pinned source.
- `examples/` with a reproducible rug-pull demo.

### Fixed
- `tools/list`, `resources/list` and `prompts/list` now follow `nextCursor` pagination. Before this, servers that paginate were silently pinned with only their first page. A repeating cursor or more than 1000 pages is an error, never a silent truncation.
- Server stderr is captured, and its tail is shown when the server crashes or times out. It was previously discarded.
- Messages over 16 MiB and listings over 50,000 entries are refused instead of exhausting memory.
- The diff walk is iterative, and paths are tuples internally, so tool names containing dots stay unambiguous.
- Writes are atomic. Piping output into `head` no longer prints a traceback, and fails closed.

### Hardening (panel review)
- GitHub output can't be hijacked. The text block is wrapped in `::stop-commands::<random token>`, annotation text is percent-escaped, server stderr has `::` defused, and control characters in names are flagged.
- `--ignore` globs match per path segment (`*` no longer crosses dots; `**` crosses any depth; `\.` is a literal dot), so a pattern can't hide a new tool whose name contains a dot.
- Signed payload v3 includes a monotonic `seq` and `snapshot_at`. `check --previous-lock`, and the Action's `previous-lock-ref`, reject rollback. The Action can read signers from a protected ref (`allowed-signers-ref`) or a secret (`allowed-signers-content`).
- 64 MiB total cap per server and per listing file.
- Every string value is scanned (`default`, `enum`, `const`, `examples`, unknown fields), not just descriptions. Text over the cap is `high`, and its head and tail are both scanned.
- New signals: whole words in Latin look-alike scripts, base64 blobs that decode to text (scanned recursively), HTML comments, split or leetspeak instruction evasions, and control characters.
- Fewer false positives: "pass your API key in … see https://docs" and "you must first call …" no longer alert, and URLs are allowed in `uri` fields.
- File modes are preserved (new files get 0644 minus umask). Markdown titles are escaped, and URLs, emails and mentions are not auto-linked.
- Windows: stdout and stderr use `errors=backslashreplace`, and commands resolve via `shutil.which` (`npx` → `npx.cmd`).

### Compatibility
- **`check --fail-on` now defaults to `low`**: an `info`-only change, such as a bare server version bump, no longer fails. Use `--fail-on info` for 0.1's any-drift behaviour.
- **Ignore globs that relied on `*` crossing dots** (e.g. `tools.*.description` meaning any depth) must now use `**`.
- `check --json` keeps the exact 0.1 output shape. The richer output is `--format json`.
- 0.1 lockfiles (without `digests`) are still read.
- Duplicate tool, prompt or resource names are now kept as `name#dup2` instead of the last one silently winning. On a server with duplicates, this shows as drift against a 0.1 lock.

## 0.1.0
- Initial release: `snapshot` and `check` for stdio MCP servers.
