# 40mcp attack-surface map

**Scope:** bridge, reverse bridge, webhook listener, OpenAPI loader, SSRF guard, egress envelope strip, Slowloris / server timeouts, in-flight cap. Connect/mixer upstream paths, vault/policy, and SSE transport are documented but not probed — see §4.

**Method:** red-team probes, one per hardening invariant, run sequentially against loopback servers in `scripts/stress-test/attack-surface.mjs`. Each probe declares an expected outcome; the runner compares expected vs. actual and emits a PASS/FAIL verdict.

```bash
node scripts/stress-test/simulate.mjs          # full
node scripts/stress-test/simulate.mjs --fast   # 5s usage window
node scripts/stress-test/simulate.mjs --probes # probes only
```

Generated output lands in `scripts/stress-test/results/` (gitignored). The harness is non-destructive and binds only to loopback.

## 1. Trust boundaries

40mcp has six places where untrusted bytes cross into trusted dispatch. Each has a distinct threat model and a distinct set of invariants the code enforces.

| # | Boundary | Ingress | Who speaks | Primary defenses |
|---|----------|---------|------------|-----------------|
| B1 | **MCP client → bridge** | stdio/SSE `CallToolRequest` | local / remote MCP clients | `validateToolArgs`, `scanReservedKeys` (recursive), `DANGEROUS_KEYS`, global dispatch cap, audit log |
| B2 | **REST client → reverse bridge** | HTTP POST `/api/tools/:name` | any HTTP speaker | `parseBody` (1 MiB cap, 15 s read timeout, strict Content-Type), `checkAuth` (constant-time), `validateToolArgs` at ingress, `stripInternalEnvelopes` at egress, CORS locked to configured origin, loopback-or-auth bind policy |
| B3 | **Webhook sender → listener** | HTTP POST `/hooks/*` | 3rd-party webhook senders | HMAC-SHA256 signature via `timingSafeEqual`, replay-window guard (strict integer timestamp, ±5 s skew, `window` seconds past), per-route + global in-flight caps, `SAFE_PATH_PATTERN` at config time, rate-limited failure logging, async-dispatch backpressure |
| B4 | **Upstream MCP (connect) → bridge** | stdio/SSE client → upstream `CallToolRequest` | upstream MCP servers | Reserved-key egress strip (`RESERVED_ENVELOPE_KEYS`), recursive depth cap, audit log passthrough |
| B5 | **Upstream REST (dispatch) → bridge** | `createApiClient` → `fetch` | external REST APIs | `assertSafeUrl` (no `file://`, no private IP literals on Location redirect), `applyResponseTransform` runs on untrusted payload |
| B6 | **Config loader → bridge** | `.json` / `.yaml` / `.har` from disk | whoever wrote the config | `MAX_OPENAPI_FILE_BYTES` (50 MiB) stat-first, `$ref` walker guarded by `DANGEROUS_KEYS`, `assertValidConfig`, tool-name sanitizer, env-var resolver with `assertSafeUrl` on server URLs |

## 2. Probe families

The harness groups probes by the boundary and defense they exercise.

### Reverse-bridge ingress (B2)

| Family | Invariant tested |
|--------|------------------|
| `proto-pollution` | `__proto__` smuggled in args is rejected at `validateToolArgs` |
| `reserved-tenant` | `_tenant` at top level is rejected |
| `nested-reserved` | `_tenant` nested inside an `object` param is caught by the recursive scanner |
| `nan-integer` | `null` where an integer is required is rejected as type-mismatch |
| `missing-required` | Missing required field is rejected with the documented message |
| `unknown-tool` | Unknown tool name returns 404 |
| `body-too-large` | Bodies over the 1 MiB cap are destroyed pre-parse |
| `wrong-content-type` | Non-JSON Content-Type is refused before body parse |
| `auth-bypass` (A1–A4) | Missing / short / unset-env auth variants all return 401 or refuse construction |

### Webhook listener (B3)

| Family | Invariant tested |
|--------|------------------|
| `hmac-wrong-secret` (W1) | HMAC with wrong secret returns 401 |
| `hmac-tampered-body` (W2) | Sign-A-send-B returns 401 |
| `replay-missing-ts` (W3) | Replay-window-on + missing timestamp returns 401 |
| `replay-scientific-notation` (W4) | `x-webhook-timestamp: 1e10` rejected by the strict-integer parser |
| `route-traversal` (W5) | `/hooks/../evil` at construction throws |
| `empty-routes` (W6) | Empty `routes: []` at construction throws |
| `replay-past-window` (W7) | Past timestamp outside the replay window returns 401 |
| `webhook-inflight-cap` (WIF1) | Per-route concurrent cap returns 429 for excess |

### SSRF guard (B5)

| Family | Invariant tested |
|--------|------------------|
| `ssrf-url-scheme` (B5-U) | `file://`, bad schemes, private IP literals, cloud-metadata all throw |
| `ssrf-loopback-redirect` (B5-LL) | Redirect chain to loopback refuses without exfil |
| `ssrf-cloud-metadata-redirect` (B5-CM) | Redirect to IMDS is refused unconditionally |

### OpenAPI loader (B6)

| Family | Invariant tested |
|--------|------------------|
| `openapi-ref-walker` (O1) | `$ref` walker refuses `__proto__`, `constructor`, `prototype` |
| `openapi-spec-size-dos` (O2) | Oversize specs are stat-rejected pre-parse |
| `openapi-collision` | Duplicate `operationId` values are caught at load |

### Egress strip

| Family | Invariant tested |
|--------|------------------|
| `egress-strip` (EG1) | All `RESERVED_ENVELOPE_KEYS` are stripped from dispatch results before egress |
| `egress-strip-nested` (EG2) | Reserved keys at depth ≤ `MAX_STRIP_DEPTH` are stripped |
| `egress-strip-rest` (EG3, EG4) | REST-path egress strip covers top-level and nested keys from upstream responses |

### Composition / intersection (compose chains × tenant scope × reverse bridge × OpenAPI loader)

| Family | Invariant tested |
|--------|------------------|
| `chain-cycle` (CMP1) | Invocation-level cycle (A→B→A) is refused before any step runs |
| `chain-depth` (CMP2) | Depth inflation via `maxDepth` clamps to `MAX_CHAIN_DEPTH` |
| `chain-tenant-propagation` (CMP3) | `_tenant` non-enumerable envelope propagates to every sub-step |
| `chain-tenant-forgery` (CMP4) | POST body `_tenant` is rejected at ingress and not observed by sub-dispatch |
| `chain-error-sanitize` (CMP5) | Optional-step errors reduce to `{_error, _error_code}` |
| `chain-as-reserved` (CMP6) | Chain step `as:` with reserved names is refused at execution |
| `chain-tenant-transitive` (CMP7) | Tenant allowlist / blocklist holds across chain sub-dispatches |
| `chain-policy-transitive` (CMP12) | Policy-gate `deny` / `require_approval` holds across chain sub-dispatches |

### HAR loader

| Family | Invariant tested |
|--------|------------------|
| `har-entry-ceiling` (HAR1) | Programmatic entries above the ceiling are refused pre-processing |
| `har-ssrf-baseurl` (HAR2) | Cloud-metadata baseUrl is refused |
| `har-sensitive-params` (HAR3) | `password` / `api_key` / `access_token` params are filtered from inferred tool inputs |
| `har-sensitive-headers` (HAR4) | `Authorization` / `Cookie` / `X-API-Key` headers are not embedded in tool defs |

### Slowloris / deployment

| Family | Invariant tested |
|--------|------------------|
| `slowloris-headers` (SL1) | `headersTimeout` closes stalled partial-header connections |

## 3. Realistic usage simulation

A six-bucket mixed workload runs against a freshly-started reverse bridge. The simulator picks buckets by weight (valid lookups, valid creates, lists, large reports, malformed-args 400s, missing-auth 401s), records per-bucket latency + status histograms, and emits them alongside the probe results. Purpose: a sustained-load sanity check that none of the defenses above degrade throughput or leak memory under load.

## 4. What is NOT in scope

Documented gaps, to be added in follow-up passes:

1. **Connect flows (B4)** — upstream-MCP egress strip needs a mocked upstream returning crafted tool results with smuggled envelope keys.
2. **Upstream REST dispatch (B5) — extended redirect chain** — `createApiClient` limits redirects to 5 hops; a 6-hop chain would confirm the hop limit fires.
3. **SSE transport** — requires a real MCP SDK client to drive.
4. **Vault daemon** — AES-256-GCM envelope crypto, JIT token retrieval. No probes yet for key rotation or replay across sessions.
5. **Policy gate** — human-in-the-loop approver. Worth modeling a hostile approver that always denies.
6. **Multi-tenant scope** — cross-tenant dispatch isolation with a shared dispatch cap.
7. **Steering** — probe that smuggles prompt injection via steering classification / instruction strip.
