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
pnpm dev
```

The API listens on `http://localhost:4100`; interactive documentation is at `/docs` and health is at `/health`.

## First end-to-end flow

1. Create a principal with `POST /v1/principals`.
2. Register its agent with `POST /v1/agents`.
3. Add a policy with `POST /v1/policies`.
4. Request authority with `POST /v1/approval-requests`.
5. If pending, decide with `POST /v1/approval-requests/:id/decision`.
6. Exchange an approved request at `POST /v1/capability-grants`.
7. Find providers via `GET /v1/discovery?capability=...`.

## Security boundary

The MVP issues signed authorization grants. It deliberately does not store or return upstream secrets yet. Provider-specific token exchange and proxied execution belong in the next milestone, after authentication, key rotation, revocation, and tenant isolation are hardened.
