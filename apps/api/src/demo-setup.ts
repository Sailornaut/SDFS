import "dotenv/config";
import { db } from "@sdfs/db";
import { generateApiKey } from "./auth.js";

const principal = await db.principal.findFirst({ orderBy: { createdAt: "asc" } });
if (!principal) throw new Error("No principal exists. Run pnpm bootstrap -- \"Your organization\" first.");
const principalId = principal.id;

const agent = await db.agent.upsert({
  where: { principalId_name: { principalId, name: "SDFS deployment demo" } },
  update: { description: "Agent exercising the complete SDFS approval and provider flow" },
  create: { principalId, name: "SDFS deployment demo", description: "Agent exercising the complete SDFS approval and provider flow" }
});
const existingPolicy = await db.policy.findFirst({ where: { principalId, name: "Production deployments require human approval" } });
const policyData = { capabilityPattern: "deploy.production", effect: "REQUIRE_APPROVAL" as const, priority: 10, enabled: true };
const policy = existingPolicy
  ? await db.policy.update({ where: { id: existingPolicy.id }, data: policyData })
  : await db.policy.create({ data: { principalId, name: "Production deployments require human approval", ...policyData } });
const provider = await db.provider.upsert({
  where: { slug: "sdfs-demo-deploy" },
  update: { baseUrl: process.env.SDFS_PROVIDER_URL ?? "http://localhost:4300" },
  create: { name: "SDFS Demo Deployment Provider", slug: "sdfs-demo-deploy", baseUrl: process.env.SDFS_PROVIDER_URL ?? "http://localhost:4300", description: "Reference capability provider for the SDFS agent handshake" }
});
await db.capability.upsert({
  where: { providerId_name_version: { providerId: provider.id, name: "deploy.production", version: "1.0" } },
  update: { availability: "ACTIVE" },
  create: {
    providerId: provider.id, name: "deploy.production", version: "1.0", availability: "ACTIVE",
    description: "Idempotently deploy a named service version to the simulated production environment",
    inputSchema: { type: "object", required: ["environment", "service", "version"] },
    outputSchema: { type: "object", required: ["deploymentId", "status"] },
    authMethods: ["sdfs-capability"]
  }
});

async function credential(name: string, scopes: string[], agentId?: string) {
  const generated = generateApiKey();
  await db.apiCredential.create({ data: { principalId, agentId, name, scopes, keyPrefix: generated.prefix, secretHash: generated.secretHash } });
  return generated.apiKey;
}

const agentKey = await credential("Demo deployment agent runtime", ["approvals:request", "approvals:read", "grants:issue"], agent.id);
const providerKey = await credential("Demo deployment provider runtime", ["grants:introspect", "grants:consume"]);

console.log(`\nAdd these values to .env (they are shown only once):\n
SDFS_DEMO_PRINCIPAL_ID=${principalId}
SDFS_DEMO_AGENT_ID=${agent.id}
SDFS_DEMO_AGENT_API_KEY=${agentKey}
SDFS_PROVIDER_API_KEY=${providerKey}\n
Then run: pnpm dev:demo\nIn another terminal run: pnpm demo:agent\n`);
console.log(`Dashboard approval policy ready: ${policy.name}`);
await db.$disconnect();
