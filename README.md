# mcpdrift

Pin your MCP servers' **tool surface** — tool names, descriptions, input schemas, resources and prompts — in a reviewable lockfile, and fail CI when an update silently changes what a server exposes.

MCP servers get upgraded by version ranges, transitive deps and config edits. A tool your agent relied on can lose an argument, change type, or disappear entirely, and nothing tells you until a run misbehaves. `mcpdrift` turns that surface into a contract.

## Install

```bash
pip install mcpdrift
```

## Usage

```bash
# record what the server exposes today (writes a reviewable lockfile)
mcpdrift snapshot --config .mcp.json --server myserver --out mcp.lock.json

# fail CI when the live surface no longer matches the lock
mcpdrift check --config .mcp.json --lock mcp.lock.json
```

The config file is a Claude-Desktop-style `.mcp.json`:

```json
{
  "mcpServers": {
    "myserver": { "command": "uvx", "args": ["some-mcp-server"] }
  }
}
```

`check` exits `1` when drift is found and prints every added, removed or changed path:

```
removed tools.read: {'description': 'read a doc', ...}
changed tools.search.inputSchema.properties.q.type: 'string' -> 'integer'
```

### Ignoring intentional changes

```bash
mcpdrift check --config .mcp.json --lock mcp.lock.json \
  --ignore 'server.version' --ignore 'tools.search.description'
```

Patterns are globs matched against the dotted path (`server.*`, `tools.*`, `prompts.*`). Ignoring a node hides every finding beneath it.

### CI

```yaml
- run: pip install mcpdrift
- run: mcpdrift snapshot --config .mcp.json --server myserver --out mcp.lock.json.new
- run: diff <(mcpdrift check --config .mcp.json --lock mcp.lock.json --json) /dev/null
```

Or simply run `mcpdrift check` as a required status check; a non-zero exit blocks the merge that bumped the server.

## How it works

`mcpdrift` launches the configured server, speaks newline-delimited JSON-RPC over stdio (the MCP stdio transport): `initialize` → `notifications/initialized` → `tools/list` + `resources/list` + `prompts/list`. Servers that don't implement a listing method simply yield an empty section. The result is canonicalized (keys sorted recursively) so comparisons are stable, then diffed structurally against the lockfile.

## Notes

- Snapshots are local and offline-friendly; nothing phones home.
- The lockfile records `server.version`, so an honest version bump shows as a one-line drift you can `--ignore` if you only care about the schema.

## License

MIT-style: use it, ship it, no warranty.
