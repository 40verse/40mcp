# Example: GitHub + Stripe Compound Chain

A compound chain that fetches a GitHub issue and then looks up the Stripe customer referenced in the issue body — in a single tool call.

## What this demonstrates

`get_issue_with_payment_status` calls two APIs in sequence:

1. `get_issue` — fetches the GitHub issue
2. `get_customer` — fetches the Stripe customer whose ID is referenced in the issue body

The chain resolves `$issue.body_stripe_customer_id` — a field extracted from the issue body that contains a line like:

```
stripe_customer: cus_xxx
```

The MCP client sees one tool, one call, one merged result.

## Prerequisites

```bash
export GITHUB_TOKEN=<your-github-token>
export STRIPE_SECRET_KEY=sk_test_your_key_here
```

## Run it

```bash
npx 40mcp serve examples/github-stripe-compound/bridge.json
```

Then call the compound tool from any MCP client:

```json
{
  "tool": "get_issue_with_payment_status",
  "args": { "owner": "acme", "repo": "billing", "issue_number": 42 }
}
```

## How the chain syntax works

In `bridge.json`, the chain is declared at the tool level:

```json
{
  "name": "get_issue_with_payment_status",
  "chain": [
    { "call": "get_issue", "as": "issue", "args": { ... } },
    { "call": "get_customer", "as": "customer", "args": { "customer_id": "$issue.body_stripe_customer_id" } }
  ]
}
```

- `"as": "issue"` — binds the first result to the `$issue` namespace
- `$issue.body_stripe_customer_id` — a field reference resolved from the first step's response
- Steps that don't depend on each other can run in parallel; 40mcp detects this automatically
- Recursion depth is capped at 10 by default (`config.chain.maxDepth`)

See [SPEC.md §2](../../SPEC.md) and the `executeChain` API for full chain syntax.
