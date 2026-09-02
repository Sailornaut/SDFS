# SecureDFS

SecureDFS is an agent control plane: discover capabilities, determine whether an agent may act, obtain human approval where required, mint narrowly scoped authorization, and preserve an audit trail.

## Modules

- **SDFS Identity** — principals, agents, providers, and ownership
- **SDFS Approve** — policies and human-in-the-loop decisions
- **SDFS Access** — short-lived signed capability grants (not raw secrets)
- **SDFS Discover** — machine-readable provider capability registry
- **SDFS Audit** — append-only action and authorization history

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

The SDK polls only while a request is pending, supports abort signals and timeouts, and refuses a second redemption locally. The API independently enforces single-use redemption.

After pulling a schema change, run `pnpm db:migrate` before restarting the API.

## Security boundary

The MVP issues signed authorization grants. It deliberately does not store or return upstream secrets yet. Provider-specific token exchange and proxied execution belong in the next milestone, after authentication, key rotation, revocation, and tenant isolation are hardened.
