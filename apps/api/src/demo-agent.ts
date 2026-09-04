import "dotenv/config";
import { randomUUID } from "node:crypto";
import { SDFS } from "@securedfs/sdk";

const apiKey = process.env.SDFS_DEMO_AGENT_API_KEY;
const principalId = process.env.SDFS_DEMO_PRINCIPAL_ID;
const agentId = process.env.SDFS_DEMO_AGENT_ID;
const providerUrl = process.env.SDFS_PROVIDER_URL ?? "http://localhost:4300";
if (!apiKey || !principalId || !agentId) throw new Error("Demo identity is missing. Run pnpm demo:setup and add its values to .env.");

const sdfs = new SDFS({ apiKey, principalId, agentId, baseUrl: process.env.SDFS_API_URL, pollIntervalMs: 1000 });
console.log("Agent: requesting deploy.production authority…");
const approval = await sdfs.request({
  capability: "deploy.production",
  reason: "Release the reference dashboard through the SDFS provider handshake",
  resource: { environment: "production", service: "sdfs-dashboard", version: "0.2.0" },
  expiresInSeconds: 3600
});
console.log(`SDFS: ${approval.approval.status}. Open http://localhost:4200 to decide request ${approval.approval.id}`);
await approval.waitForDecision({ timeoutMs: 60 * 60_000 });
if (!approval.approved) throw new Error(`Agent: deployment ${approval.approval.status.toLowerCase()}.`);
console.log("Agent: approved. Redeeming one short-lived capability grant…");
const { token } = await approval.redeem(300);
const idempotencyKey = randomUUID();
const response = await fetch(`${providerUrl}/v1/deployments`, {
  method: "POST",
  headers: { authorization: `Bearer ${token}`, "idempotency-key": idempotencyKey }
});
const result = await response.json();
if (!response.ok) throw new Error(`Provider returned ${response.status}: ${JSON.stringify(result)}`);
console.log("Provider: deployment completed.");
console.log(JSON.stringify(result, null, 2));
