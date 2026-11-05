# Changelog

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

### Compatibility
- `check --json` keeps the exact 0.1 output shape. The richer output is `--format json`.
- The default `--fail-on` is `info`, so any drift still fails, as in 0.1.
- 0.1 lockfiles (without `digests`) are still read.
- Duplicate tool, prompt or resource names are now kept as `name#dup2` instead of the last one silently winning. On a server with duplicates, this shows as drift against a 0.1 lock.

## 0.1.0
- Initial release: `snapshot` and `check` for stdio MCP servers.
