import assert from "node:assert/strict";
import test from "node:test";
import { SDFS, SDFSError } from "./index.js";

const approval = { id: "approval_1", principalId: "principal_1", agentId: "agent_1", capability: "deploy.production", reason: "ship", resource: {}, status: "PENDING", expiresAt: new Date(Date.now() + 60_000).toISOString() };

test("simulated agent waits for a human and redeems exactly once", async () => {
  let polls = 0;
  const calls: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const url = String(input); calls.push(`${init?.method ?? "GET"} ${url}`);
    if (url.endsWith("/v1/approval-requests") && init?.method === "POST") return Response.json(approval, { status: 201 });
    if (url.endsWith("/v1/approval-requests/approval_1")) return Response.json({ ...approval, status: ++polls > 1 ? "APPROVED" : "PENDING" });
    if (url.endsWith("/v1/capability-grants")) return Response.json({ grant: { id: "grant_1", tokenId: "token_1", expiresAt: approval.expiresAt }, token: "signed.jwt.value" }, { status: 201 });
    return Response.json({ error: "not_found" }, { status: 404 });
  };
  try {
    const client = new SDFS({ apiKey: "sdfs_agent.secret", principalId: "principal_1", agentId: "agent_1", pollIntervalMs: 1 });
    const handle = await client.request({ capability: "deploy.production", reason: "ship" });
    await handle.waitForDecision({ timeoutMs: 100 });
    assert.equal(handle.approved, true);
    const grant = await handle.redeem();
    assert.equal(grant.token, "signed.jwt.value");
    await assert.rejects(() => handle.redeem(), (error: unknown) => error instanceof SDFSError && error.code === "approval_not_redeemable");
    assert.equal(calls.filter(call => call.includes("capability-grants")).length, 1);
  } finally { globalThis.fetch = originalFetch; }
});

test("receives an approval through the authenticated event stream without polling", async () => {
  const calls: string[] = [];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    const url = String(input); calls.push(url);
    if (url.endsWith("/v1/approval-requests") && init?.method === "POST") return Response.json(approval, { status: 201 });
    if (url.endsWith("/events")) {
      const approved = { ...approval, status: "APPROVED" };
      return new Response(`event: approval\ndata: ${JSON.stringify(approval)}\n\nevent: approval\ndata: ${JSON.stringify(approved)}\n\n`, { headers: { "content-type": "text/event-stream" } });
    }
    return Response.json({ error: "unexpected_request" }, { status: 500 });
  };
  try {
    const client = new SDFS({ apiKey: "sdfs_agent.secret", principalId: "principal_1", agentId: "agent_1", pollIntervalMs: 1 });
    const handle = await client.request({ capability: "deploy.production", reason: "ship" });
    await handle.waitForDecision({ timeoutMs: 100 });
    assert.equal(handle.approval.status, "APPROVED");
    assert.equal(calls.some(call => call.endsWith("/v1/approval-requests/approval_1")), false);
  } finally { globalThis.fetch = originalFetch; }
});
