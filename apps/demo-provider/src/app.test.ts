import assert from "node:assert/strict";
import test from "node:test";
import { createProviderApp, ProviderError, type GrantClient, type GrantDetails } from "./app.js";

const valid: GrantDetails = { active: true, consumable: true, grantId: "grant_1", agentId: "agent_1", capability: "deploy.production", resource: { environment: "production", service: "dashboard", version: "0.2.0" } };

function client(overrides: Partial<GrantClient> = {}): GrantClient {
  return { introspect: async () => valid, consume: async () => ({ ...valid, replayed: false }), ...overrides };
}

test("executes once and returns a stable result for an idempotent replay", async () => {
  let calls = 0;
  const app = createProviderApp(client({ consume: async () => ({ ...valid, replayed: calls++ > 0 }) }));
  const first = await app.inject({ method: "POST", url: "/v1/deployments", headers: { authorization: "Bearer signed.grant", "idempotency-key": "release-001" } });
  const second = await app.inject({ method: "POST", url: "/v1/deployments", headers: { authorization: "Bearer signed.grant", "idempotency-key": "release-001" } });
  assert.equal(first.statusCode, 201);
  assert.equal(second.statusCode, 200);
  assert.equal(first.json().deploymentId, second.json().deploymentId);
  assert.equal(second.json().replayed, true);
  await app.close();
});

test("rejects inactive and incorrectly scoped grants before consumption", async () => {
  let consumed = false;
  const inactive = createProviderApp(client({ introspect: async () => ({ active: false }), consume: async () => { consumed = true; return valid; } }));
  const inactiveResponse = await inactive.inject({ method: "POST", url: "/v1/deployments", headers: { authorization: "Bearer revoked", "idempotency-key": "release-002" } });
  assert.equal(inactiveResponse.statusCode, 401);
  assert.equal(consumed, false);
  await inactive.close();

  const wrongScope = createProviderApp(client({ introspect: async () => ({ ...valid, capability: "deploy.staging" }), consume: async () => { consumed = true; return valid; } }));
  const scopedResponse = await wrongScope.inject({ method: "POST", url: "/v1/deployments", headers: { authorization: "Bearer wrong", "idempotency-key": "release-003" } });
  assert.equal(scopedResponse.statusCode, 403);
  assert.equal(consumed, false);
  await wrongScope.close();
});

test("rejects a grant consumed by a different operation", async () => {
  const app = createProviderApp(client({ consume: async () => { throw new ProviderError(409, "capability_grant_already_consumed"); } }));
  const response = await app.inject({ method: "POST", url: "/v1/deployments", headers: { authorization: "Bearer used", "idempotency-key": "release-004" } });
  assert.equal(response.statusCode, 409);
  assert.equal(response.json().error, "capability_grant_already_consumed");
  await app.close();
});
