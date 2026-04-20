# 40mcp — The Four-Dimensional MCP Bridge

> A 40verse project. The name is not a version number.

---

## Why This Exists

Most tools solve one problem. They draw a line from A to B and call it done.

40mcp is not most tools. It is a tesseract — a four-dimensional hypercube where each dimension doesn't just add capability, it *folds the previous dimension into itself* and causes something entirely new to emerge.

The number 40 is the fourth dimension. Every 40verse project builds upward through the same structure. You don't understand 40mcp by reading the API surface. You understand it by watching the shape evolve.

---

## The Tesseract Diagram

```
Dimension 1         Dimension 2         Dimension 3         Dimension 4
(Point → Line)      (Line → Plane)      (Plane → Cube)      (Cube → Tesseract)

     •——————•         ══════════          ╔═════════╗         ╔═════════╗
                      ══════════          ║         ║        /║        /║
   REST API           OpenAPI             ║  Mixer  ║       ╔═════════╗ ║
      ↓               GraphQL             ║  Chain  ║       ║Reverse  ║ ║
   MCP Tools          HAR replay          ║  Shape  ║       ║Bridge   ║/
                          ↓               ╚═════════╝       ╚═════════╝
                      MCP Tools              ↓                   ↓
                                         MCP Tools           ∞ (self-referential)
```

---

## Dimension 1: The Line

**REST Bridge — Point becomes Line**

`createRestBridge()` takes one REST API and maps it to MCP tools. This is a straight line — input enters at one end, MCP tools emerge at the other.

The primitive capability: *any HTTP surface becomes an LLM-callable interface.*

Without Dimension 1, nothing exists. The line is the foundation. But a line has no width. It cannot hold complexity. It knows only one thing at a time.

**What emerges:** HTTP becomes MCP. Existing REST APIs become callable by LLM-based agents via MCP, without rewriting the underlying service.

---

## Dimension 2: The Plane

**Loaders — Line becomes Plane**

The line had one input: a REST endpoint you described manually. The plane has many: OpenAPI specifications, GraphQL introspection endpoints, HAR traffic recordings captured from real sessions.

Multiple protocols converge onto the same tool surface. The plane is not three separate lines — it is a single surface that any of those input sources can populate.

**What emerges:** Discovery. You don't have to know the API before you use it. The system reads what the API says about itself. The tool surface self-generates from evidence rather than manual description.

The HAR loader is the first whisper of what Dimension 4 will say loudly: the traffic that flows *through* a bridge can be watched and turned into the *definition* of that bridge.

---

## Dimension 3: The Cube

**Composition — Plane becomes Cube**

The plane was many sources feeding one surface. The cube is that surface interacting with itself.

The Mixer combines multiple APIs into one MCP server. Chains compose multiple tools into single operations — the output of one becomes the input of the next. Response transforms shape what comes out before the LLM ever sees it.

The plane gains depth. Tools are no longer independent. They relate. They compose. A chain is a higher-order tool: a tool made of tools.

**What emerges:** Workflow. The LLM stops orchestrating individual HTTP calls and starts calling complete operations. Complexity is absorbed into the tool surface and hidden from the caller.

---

## Dimension 4: The Tesseract

**Reverse Bridge — Cube folds into itself**

This is where the geometry becomes strange.

The Reverse Bridge inverts the direction. MCP tools become REST endpoints. The system that consumed HTTP now *emits* HTTP. Input becomes output. The bridge works in both directions.

But this is not merely symmetry. When you fold the cube back on itself, something self-referential becomes possible that had no path to existence in three dimensions:

> 40mcp can wrap itself.

Here is the loop:
1. A reverse bridge exposes MCP tools as REST endpoints
2. HAR capture watches the traffic flowing through those endpoints
3. The HAR loader reads that traffic and generates new MCP tools
4. Those tools feed a new bridge

The system observes its own output and generates its own input. The tool-generation machinery is itself a tool. The traffic that tests the bridge is the same traffic that defines the bridge.

**What emerges:** Self-reference without paradox. The system becomes capable of describing itself, watching itself, and reconstructing itself from evidence. This is not a feature. It is a structural property of the fourth dimension.

---

## The Tesseract Folded — Trust Topology

The fourth dimension gives you a bridge that points both ways. When you chain two of them together and add a third, you get a *trust gradient* — a shape the previous dimensions cannot produce.

```
  Instance 3                Instance 1                Instance 2              upstream
  (external                 (gateway)                 (backend +              (real API)
   client)                                             sealed vault)
      │                         │                         │                      │
      │   CLIENT_TOKEN          │                         │                      │
      ├────────────────────────▶│                         │                      │
      │                         │                         │                      │
      │                         │   PROXY_TOKEN           │                      │
      │                         ├────────────────────────▶│                      │
      │                         │                         │                      │
      │                         │                         │   DEEP_SECRET        │
      │                         │                         ├─────────────────────▶│
      │                         │                         │                      │
      │      ───direct───       │                         │                      │
      ├ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶◉ 401
      │                                                  (refused at auth layer,
      │                                                   not at the network)
```

Three 40mcp instances, three separate trust zones. Each edge is a different credential. Each fold is enforced at the application layer, not the network.

- **Instance 2** holds `DEEP_SECRET` — the real upstream credential — in a closure that never leaves its process. It accepts inbound calls only if they present `PROXY_TOKEN`, and runs a policy gate that refuses destructive tools even when auth passes.
- **Instance 1** holds `PROXY_TOKEN` only. It has no vault, no deep credentials, no knowledge of what `DEEP_SECRET` is. It accepts `CLIENT_TOKEN` from external callers and forwards tool calls to Instance 2.
- **Instance 3** holds `CLIENT_TOKEN` only. It can reach Instance 1. It *cannot* reach Instance 2 directly — Instance 2 refuses anything that doesn't carry `PROXY_TOKEN`.

The interesting edge is the dashed one. Imagine the network controls have been bypassed — Instance 3 and Instance 2 end up on the same flat VPC by mistake, or an operator exposes Instance 2's port, or a firewall rule lapses. Network-layer isolation is gone. Instance 3 tries a direct POST to Instance 2.

**Instance 2 still refuses, at the application layer.** The auth gate rejects calls without `PROXY_TOKEN`. If `PROXY_TOKEN` itself has been stolen (fully-compromised Instance 1), the policy gate still refuses to dispatch tools marked `policy: 'deny'` or `policy: 'require_approval'`. Two layers. Each works independently.

This is **action gating that outlives network gating**. The network layer and the application layer compose: if either holds, the destructive action does not run.

The pattern is not a feature 40mcp added. It is a shape that emerges once the tesseract exists. You need a bridge that can speak REST in both directions (Dimension 4) to chain instances meaningfully, you need the composition primitives (Dimension 3) to run policy gates over chains, and you need the protocol-ingestion generality (Dimension 2) so every instance can own a different trust zone. Drop any dimension and the topology collapses — you get either one bridge or none.

The live proof is in `scripts/stress-test/three-tier-sim.mjs`. Eight probes cover the full defense-in-depth stack: auth layer, policy layer, credential isolation, and the blast-radius report for full gateway compromise. Run it before every release.

```bash
node scripts/stress-test/three-tier-sim.mjs
```

When all eight pass, the trust topology holds. When one fails, a defense-in-depth layer has silently collapsed.

---

## The 40verse Pattern

40mcp is one tile in a larger architecture. The 40verse convention — that the number 40 signals the fourth dimension — is a commitment: every project in this ecosystem builds through the same four-phase geometric evolution.

**40link** is the orchestration layer. Where 40mcp defines and bridges tool surfaces, 40link coordinates the flows between them. The relationship is load-bearing: 40mcp produces the vocabulary (tools); 40link writes the sentences (workflows).

The tesseract property of 40mcp makes it uniquely useful to an orchestrator: because 40mcp can expose any tool surface as a REST endpoint, and ingest any REST endpoint as a tool surface, it becomes the universal adapter layer. 40link never needs to know what protocol lives upstream or downstream. 40mcp handles the fold.

---

## What Does Not Exist Below Dimension 4

| Dimension | What you can do | What you cannot do |
|-----------|----------------|-------------------|
| 1 | Map one API | Handle multiple protocols |
| 2 | Ingest any API shape | Combine them or make tools interact |
| 3 | Build complex workflows | Run them bidirectionally |
| 4 | Everything | (the question changes) |

At Dimension 4 the question stops being "what can I do with this API?" and becomes "what does this system know about itself?"

That is the only question worth asking at the fourth dimension.

---

## Design Principles

**Geometry over features.** Each dimension is not a new feature list. It is a structural transformation. Features are consequences, not causes.

**Emergence is the test.** If adding a new capability doesn't cause something to emerge that was impossible before, it belongs in the same dimension — it does not earn a new one.

**Self-reference without regression.** The tesseract folds on itself but does not collapse. The self-referential loop produces new information (a HAR recording is richer than the spec that generated the traffic) rather than infinite recursion.

**The bridge is not the destination.** 40mcp exists to make other systems smarter, not to be smart itself. It is infrastructure, not application. The fourth dimension is still a bridge — it just bridges in every direction simultaneously.

---

*40verse. Fourth dimension forward.*

---

## Further Reading

| Document | What it covers |
|----------|---------------|
| [README.md](README.md) | Install, quick start, API examples, CLI reference |
| [SPEC.md](SPEC.md) | Normative release contract — security model, non-goals |
