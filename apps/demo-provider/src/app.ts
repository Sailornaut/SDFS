import Fastify from "fastify";
import { createHash } from "node:crypto";

export type GrantDetails = {
  active: boolean;
  replayed?: boolean;
  consumable?: boolean;
  grantId?: string;
  agentId?: string;
  capability?: string;
  resource?: unknown;
};

export type GrantClient = {
  introspect(token: string): Promise<GrantDetails>;
  consume(token: string, idempotencyKey: string): Promise<GrantDetails>;
};

type DeploymentResource = { environment: string; service: string; version: string };

function deploymentResource(value: unknown): DeploymentResource | null {
  if (!value || typeof value !== "object") return null;
  const resource = value as Record<string, unknown>;
  if (resource.environment !== "production" || typeof resource.service !== "string" || typeof resource.version !== "string") return null;
  return { environment: resource.environment, service: resource.service, version: resource.version };
}

export function createProviderApp(grants: GrantClient) {
  const app = Fastify({ logger: false });
  app.get("/health", async () => ({ status: "ok", service: "sdfs-demo-deployment-provider" }));
  app.post("/v1/deployments", async (request, reply) => {
    const authorization = request.headers.authorization;
    const idempotencyKey = request.headers["idempotency-key"];
    if (!authorization?.startsWith("Bearer ")) return reply.code(401).send({ error: "missing_capability_grant" });
    if (typeof idempotencyKey !== "string" || idempotencyKey.length < 8) return reply.code(400).send({ error: "invalid_idempotency_key" });
    const token = authorization.slice(7);
    const inspected = await grants.introspect(token);
    if (!inspected.active) return reply.code(401).send({ error: "inactive_capability_grant" });
    if (inspected.capability !== "deploy.production") return reply.code(403).send({ error: "capability_mismatch", required: "deploy.production" });
    const resource = deploymentResource(inspected.resource);
    if (!resource) return reply.code(403).send({ error: "invalid_deployment_resource" });

    let consumed: GrantDetails;
    try { consumed = await grants.consume(token, idempotencyKey); }
    catch (error) {
      const status = error instanceof ProviderError ? error.status : 502;
      return reply.code(status).send({ error: error instanceof ProviderError ? error.code : "sdfs_unavailable" });
    }
    if (!consumed.active) return reply.code(401).send({ error: "inactive_capability_grant" });
    const deploymentId = `dep_${createHash("sha256").update(`${consumed.grantId}:${idempotencyKey}`).digest("hex").slice(0, 20)}`;
    return reply.code(consumed.replayed ? 200 : 201).send({
      deploymentId, status: "SUCCEEDED", replayed: consumed.replayed ?? false,
      service: resource.service, version: resource.version, environment: resource.environment,
      authorizedBy: { grantId: consumed.grantId, agentId: consumed.agentId }
    });
  });
  return app;
}

export class ProviderError extends Error {
  constructor(public status: number, public code: string) { super(code); }
}

export function createSdfsGrantClient(options: { apiUrl: string; apiKey: string }): GrantClient {
  async function call(path: string, body: object) {
    const response = await fetch(`${options.apiUrl}${path}`, {
      method: "POST",
      headers: { authorization: `Bearer ${options.apiKey}`, "content-type": "application/json" },
      body: JSON.stringify(body)
    });
    const result = await response.json() as GrantDetails & { error?: string };
    if (!response.ok) throw new ProviderError(response.status, result.error ?? "sdfs_request_failed");
    return result;
  }
  return {
    introspect: (token) => call("/v1/capability-grants/introspect", { token }),
    consume: (token, idempotencyKey) => call("/v1/capability-grants/consume", { token, idempotencyKey })
  };
}
