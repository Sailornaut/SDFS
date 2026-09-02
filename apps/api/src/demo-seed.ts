import "dotenv/config";

const apiKey = process.env.SDFS_API_KEY;
const apiUrl = process.env.SDFS_API_URL ?? "http://localhost:4100";
if (!apiKey) throw new Error("SDFS_API_KEY is required. Export it without placing the secret in shell history.");

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiUrl}${path}`, {
    ...init,
    headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json", ...init?.headers }
  });
  if (!response.ok) throw new Error(`${init?.method ?? "GET"} ${path} returned ${response.status}: ${await response.text()}`);
  return response.json() as Promise<T>;
}

const me = await request<{ principal: { id: string; name: string } }>("/v1/me");
const suffix = new Date().toISOString().replace(/\D/g, "").slice(0, 14);
const agent = await request<{ id: string; name: string }>("/v1/agents", {
  method: "POST",
  body: JSON.stringify({ principalId: me.principal.id, name: `deployment-agent-${suffix}`, description: "Demo agent requesting production deployment authority" })
});
const policy = await request<{ id: string; name: string }>("/v1/policies", {
  method: "POST",
  body: JSON.stringify({ principalId: me.principal.id, name: `Production deployments require a human (${suffix})`, capabilityPattern: "deploy.production", effect: "REQUIRE_APPROVAL", priority: 10 })
});
const approval = await request<{ id: string; status: string }>("/v1/approval-requests", {
  method: "POST",
  body: JSON.stringify({
    principalId: me.principal.id,
    agentId: agent.id,
    capability: "deploy.production",
    reason: "Release SDFS dashboard v0.1.0 to the production environment",
    resource: { environment: "production", service: "sdfs-dashboard", version: "0.1.0" },
    expiresInSeconds: 3600
  })
});

console.log(JSON.stringify({ principal: me.principal.name, agent, policy, approval, dashboard: "http://localhost:4200" }, null, 2));
