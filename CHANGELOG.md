# Changelog

## 0.3.0 (unreleased)

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
