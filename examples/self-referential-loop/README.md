# Example: The Self-Referential Loop (The Tesseract)

40mcp wrapping itself. The tool-generation machinery is itself a tool.

## What this demonstrates

The four-step loop that closes D4 — The Tesseract:

```
Step 1: reverse   — MCP tools become REST endpoints + auto-generated OpenAPI spec
Step 2: HAR       — capture traffic to the reverse bridge as a HAR recording
Step 3: from-har  — load the HAR to generate new tool definitions
Step 4: bridge    — serve those tools as a new MCP server
```

The output of Step 4 is functionally equivalent to the input of Step 1. **40mcp has reconstructed its own tool surface from behavioral evidence, with no external spec.**

## Walkthrough

### Step 1 — reverse

Start a normal 40mcp server (use any config — petstore.json is a good starting point):

```bash
npx 40mcp serve examples/petstore.json &
```

Now run the reverse bridge against it:

```bash
npx 40mcp reverse examples/petstore.json --port 8080
```

This exposes the MCP tools as REST endpoints at `http://localhost:8080/tools/*` and serves an auto-generated OpenAPI spec at `http://localhost:8080/openapi.json`.

### Step 2 — record HAR

Open a browser or use `curl` to exercise the REST endpoints. In DevTools (Network tab), record all traffic, then export as `loop.har`. Or use a tool like `mitmproxy` for non-browser capture.

### Step 3 — from-har

```bash
npx 40mcp from-har loop.har --min-observations 1 --out loop-bridge.json
```

### Step 4 — bridge

```bash
npx 40mcp serve loop-bridge.json
```

The new server exposes the same tool surface as the original — derived entirely from observed HTTP traffic, not the original config.

## Runnable proof

The full loop is exercised automatically in the test suite:

```bash
node --experimental-vm-modules node_modules/.bin/vitest test/self-referential.test.js
```

`test/self-referential.test.js` runs all four steps programmatically using the public API (`createReverseBridge`, `loadHarFile`, `createRestBridge`) and asserts that the reconstructed tool definitions match the originals. No manual steps required.

## Why this matters

Most tools solve one problem in one direction. The self-referential loop demonstrates that 40mcp has no fixed direction:

- **Forward:** spec → tools (D1/D2)
- **Sideways:** tools → REST → spec (D4 reverse)
- **Recursive:** REST traffic → tools (D2 HAR)
- **Closed:** tools → REST → HAR → tools → ... (D4 loop)

This is API archaeology applied to 40mcp itself. Any API that can be observed can be wrapped. Including the wrapper.

See [CONCEPT.md](../../CONCEPT.md) for the full Tesseract model and why D4 is a structural transformation rather than a feature.
