# `40mcp settings show` and `40mcp doctor`

Two commands that reason across the whole configuration model — not just the bridge config. They exist to answer operator questions that used to require reading source code.

- `settings show` answers "why is it using this value?"
- `doctor` answers "will this actually run, and what might trip it up?"

This doc covers what each command knows, what it deliberately does **not** know, and when to use which.

---

## `settings show`

### What it does

Prints the merged settings tree — `40mcp.settings.json` + known env overlays + defaults — with provenance per key. Every leaf is attributed to one of:

- `env:<VAR>` — an env var that outranks the settings value at a consumption site.
- `settings.json:<path>` — value present in the loaded settings file.
- `default` — fell through to the built-in default.

```bash
$ 40mcp settings show
Loaded from /etc/40mcp/40mcp.settings.json
(settings + known env overlays + defaults; CLI flags are only resolved in a command context)

[bridge]
  bridge.transport.type   = "sse"    ← settings.json:/etc/40mcp/40mcp.settings.json
  bridge.transport.port   = 9000     ← settings.json:/etc/40mcp/40mcp.settings.json
  bridge.limits.dispatch.maxConcurrent = 50  ← default
  ...

[frontdoor]
  frontdoor.limits.sse.maxConnections = 500 ← env:MAX_SSE_CONNECTIONS
  ...

Precedence: CLI > env > settings.json > default
(CLI flag overrides everything when a command is actually run.)
```

Supports:

- `--settings <path>` — use the same explicit override the command it's auditing would use.
- `--json` — machine-readable output with one row per leaf (`{ path, value, source, secret }`).

### What it does **not** know

**CLI flags.** CLI flags only resolve in a real `serve` / `link` invocation. `settings show` does not simulate an invocation — it prints what settings + env + defaults would contribute, and reminds you that a CLI flag wins when present. If you ran `40mcp serve config.json --sse 9999`, the `--sse 9999` override is not reflected here.

**Implicit env overrides.** 40mcp does **not** apply a blanket env-over-settings precedence. Only keys in the explicit `ENV_OVERLAY` table (in `src/config/settings-show.js`) are treated as env-outranks-settings. If you set an arbitrary env var that shares a name with a settings key, it will not show up here — because the code does not actually read it at a consumption site.

The current overlay table:

| Env var | Path (as shown by `settings show`) | Valid settings-file key? | Redacted? |
|---|---|---|---|
| `MAX_SSE_CONNECTIONS` | `frontdoor.limits.sse.maxConnections` | Yes | No |
| `VAULT_DAEMON_SECRET` | `bridge.vault.daemonSecret` | **No** — provenance-only | Yes |
| `VAULT_PASSPHRASE` | `bridge.vault.passphrase` | **No** — provenance-only | Yes |

`MAX_SSE_CONNECTIONS` is the one env overlay that maps to an actual settings key — the env wins over the file at runtime. `VAULT_DAEMON_SECRET` and `VAULT_PASSPHRASE` are **runtime-only secret rows**: they appear in `settings show` so operators can confirm the credential is available (or not), but they are **not** valid `40mcp.settings.json` keys. The validator rejects them if placed in the settings file.

### Secret redaction

`VAULT_DAEMON_SECRET` and `VAULT_PASSPHRASE` surface only as `<set>` / `<unset>`, never as the secret value. The `--json` output follows the same rule and emits `"secret": true` for those rows so log redactors can strip them further downstream if they want.

### When to use

- Operator ticket: "the frontdoor is binding the wrong port" → run it, look at the provenance on `frontdoor.transport.port`.
- Before rolling a deploy: run it against the settings file to confirm env overrides are what you expect.
- After editing `40mcp.settings.json`: confirm the key you expected to be loaded actually shows `settings.json:<path>` rather than `default`.

---

## `doctor`

### What it does

`doctor` takes a bridge config (`40mcp doctor <config.json>`) and then picks up any `40mcp.settings.json` that the same discovery rules would surface — sibling of the config, or CWD. It reports:

- **Bridge-config warnings** (PII in tool names, literal credentials in headers, missing auth on non-localhost baseUrl, likely-large responses without a token budget).
- **Settings validation warnings** (propagated from the validator, e.g. SSE fields under `stdio` transport).
- **Runtime safety combinations as expressed through settings** — frontdoor / vault / env-shadow drift that the settings file would produce when the instance actually starts.

`doctor` is bridge-config-centric with settings-aware drift layered on top. It does **not** currently take a `.mcp.json` as input or audit an upstream frontdoor topology directly — it only sees frontdoor-related concerns through the `frontdoor.*` cluster of the discovered settings.

### Settings-aware runtime checks

`doctor` covers:

| Warning | Trigger |
|---|---|
| Will refuse to publish at runtime | `frontdoor.transport.type=sse` + non-loopback `host` + no `frontdoor.auth.*` |
| Tenant scoping requires multi-token auth | `frontdoor.tenantMap.path` set, but `frontdoor.auth.bearerFile` is not |
| Vault auth will fail at startup | `bridge.vault.daemon=true` but `VAULT_DAEMON_SECRET` is unset in env |
| Env will override settings | `MAX_SSE_CONNECTIONS` set in env *and* `frontdoor.limits.sse.maxConnections` set in settings (env wins) |

Some of these are **runtime-fatal indicators** — the instance will not actually start with that combination. Others are **drift warnings** — everything works, but the operator probably didn't intend it (e.g. env silently shadowing settings).

### When to use

- Before any deploy or restart: `40mcp doctor bridge.json`.
- After editing the settings file that sits next to the config: confirm no runtime drift was introduced.
- When taking over someone else's bridge config + settings pair: catch cross-layer footguns (env shadow, non-loopback without auth, vault-daemon without secret) before they reach prod.

`doctor` is additive — a zero-warning pass does not prove correctness, but a non-zero result is almost always worth investigating.

---

## How the two commands differ

| | `settings show` | `doctor` |
|---|---|---|
| Needs a bridge config? | No | Yes |
| Checks env drift? | Shows env values where overlays exist | Flags env-shadow as a warning |
| Checks runtime combinations? | No | Yes (the real point) |
| Prints every settings key? | Yes | No — only problematic ones |
| Output | Full provenance table | Warning list (empty → "No issues found") |

They compose: run `doctor` first to confirm nothing is broken, then `settings show` if you want to see exactly what each key resolves to.

---

## Related docs

- [CONFIGURATION_MODEL.md](../CONFIGURATION_MODEL.md) — precedence and identity.
- [SETTINGS.md](../SETTINGS.md) — every settings key, with recipes.
- [BRIDGE_VS_FRONTDOOR.md](../BRIDGE_VS_FRONTDOOR.md) — which cluster applies when.
