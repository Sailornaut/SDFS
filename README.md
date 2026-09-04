# SecureDFS

SecureDFS is an agent control plane: discover capabilities, determine whether an agent may act, obtain human approval where required, mint narrowly scoped authorization, and preserve an audit trail.

## Modules

- **SDFS Identity** — principals, agents, providers, and ownership
- **SDFS Approve** — policies and human-in-the-loop decisions
- **SDFS Access** — short-lived signed capability grants (not raw secrets)
- **SDFS Discover** — machine-readable provider capability registry
- **SDFS Audit** — append-only action and authorization history

The repository also contains a reference deployment provider. It demonstrates how an external service inspects an SDFS grant, validates the exact capability and resource, atomically consumes it, and safely handles retries.

## Quick start

```bash
cp .env.example .env
docker compose up -d
pnpm install
pnpm db:generate
pnpm db:migrate
pnpm bootstrap -- "Your organization"
pnpm dev
```

Run these commands from the repository root. Root scripts explicitly load the root `.env` before invoking package commands. The bootstrap command prints the only copy of an owner API credential. Store it securely, then use it to sign into the dashboard at `http://localhost:4200`. The API listens on `http://localhost:4100`; interactive documentation is at `/docs` and health is at `/health`.

## Authentication

All `/v1` routes require `Authorization: Bearer <credential>`. Credentials are random, stored only as SHA-256 hashes, and may be principal-wide or pinned to one agent. Each credential has explicit scopes and optional expiration; revocation takes effect on its next request.

The dashboard encrypts its credential with AES-256-GCM in a strict, HTTP-only, eight-hour cookie. Set a unique `DASHBOARD_SESSION_SECRET`; never reuse `SDFS_SIGNING_SECRET`.

Create and revoke additional credentials through:

- `GET /v1/credentials`
- `POST /v1/credentials`
- `POST /v1/credentials/:id/revoke`

New secrets are returned once. SDFS cannot recover them afterward.

## Demo approval

With the API and dashboard running, load an owner credential without writing it into shell history:

```bash
read -s "SDFS_API_KEY?Owner API key: "
export SDFS_API_KEY
echo
pnpm demo:seed
unset SDFS_API_KEY
```

Refresh the dashboard to decide the resulting `deploy.production` request. The seeder intentionally uses the authenticated API rather than inserting database rows, so agent creation, policy evaluation, tenant checks, and audit events are all exercised.

## First end-to-end flow

1. Bootstrap the principal and owner credential from the trusted server console.
2. Register its agent with `POST /v1/agents`.
3. Create an agent-pinned credential with only `approvals:request` and `grants:issue`.
4. Add a policy with `POST /v1/policies`.
5. Request authority with `POST /v1/approval-requests`.
6. If pending, decide in the dashboard or with `POST /v1/approval-requests/:id/decision`.
7. Exchange an approved request at `POST /v1/capability-grants`.

Each approval can be exchanged exactly once. Redemption atomically changes the request to `GRANTED`, so retries or competing agent processes cannot mint duplicate grants. Grants can be checked with `POST /v1/capability-grants/introspect` and revoked with `POST /v1/capability-grants/:id/revoke`.

## Agent SDK

Create an agent-pinned runtime credential in the dashboard's **Agent access** panel. Its secret is displayed once, so copy it into the agent's secret store before leaving the page.

```ts
import { SDFS } from "@securedfs/sdk";

const sdfs = new SDFS({
  baseUrl: "http://localhost:4100",
  apiKey: process.env.SDFS_API_KEY!,
  principalId: process.env.SDFS_PRINCIPAL_ID!,
  agentId: process.env.SDFS_AGENT_ID!
});

const approval = await sdfs.request({
  capability: "deploy.production",
  reason: "Release SDFS dashboard v0.2.0",
  resource: { environment: "production" }
});

await approval.waitForDecision({ timeoutMs: 15 * 60_000 });
if (!approval.approved) throw new Error(`Deployment ${approval.approval.status}`);

const { token } = await approval.redeem(900);
// Present the short-lived token to the capability provider.
```

The SDK waits on an authenticated Server-Sent Events stream while a request is pending, supports abort signals and timeouts, and falls back to polling when streaming is unavailable. It refuses a second redemption locally, while the API independently enforces single-use redemption.

Raw clients can subscribe with `GET /v1/approval-requests/:id/events` using the same bearer credential as the request. The stream immediately sends the current snapshot, emits subsequent state changes as `approval` events, sends heartbeats while pending, and closes after a terminal decision.

After pulling a schema change, run `pnpm db:migrate` before restarting the API.

## Complete provider handshake demo

First prepare a least-privilege agent identity and provider identity. This command writes the records to the local database and prints both credentials exactly once:

```bash
pnpm demo:setup
```

Copy the four generated values (`SDFS_DEMO_*` plus `SDFS_PROVIDER_API_KEY`) into `.env`, then start SDFS, the dashboard, and the reference provider:

```bash
pnpm dev:demo
```

In a second terminal:

```bash
pnpm demo:agent
```

The root demo command builds the local SDK package automatically before starting the agent, so it also works from a fresh clone.

The agent creates a `deploy.production` request and waits. Open `http://localhost:4200`, approve it once, and watch the agent redeem the approval and call the provider on port 4300.

The provider does not receive an SDFS signing secret. It authenticates to SDFS with a principal-owned credential limited to `grants:introspect` and `grants:consume`. Consumption is atomic and keyed by the provider credential plus the request's `Idempotency-Key`: an identical retry returns the same deployment identifier, while another operation cannot reuse the grant.

Provider endpoints:

- `GET http://localhost:4300/health`
- `POST http://localhost:4300/v1/deployments`
- `POST /v1/capability-grants/introspect` on SDFS
- `POST /v1/capability-grants/consume` on SDFS

## Security boundary

The MVP issues signed authorization grants and supports provider-side inspection and one-time consumption. It deliberately does not store or return upstream secrets, perform real deployments, or yet establish trust between providers and principals in different tenants. Provider federation, asymmetric signing/key rotation, and proxied upstream credentials remain later milestones.
