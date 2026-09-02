import "dotenv/config";
import Fastify from "fastify";
import swagger from "@fastify/swagger";
import swaggerUi from "@fastify/swagger-ui";
import { SignJWT } from "jose";
import { randomUUID } from "node:crypto";
import { db, Prisma, RequestStatus } from "@sdfs/db";
import {
  createAgentSchema, createApprovalRequestSchema, createCapabilitySchema,
  createCredentialSchema, createGrantSchema, createPolicySchema,
  createProviderSchema, decisionSchema
} from "@sdfs/contracts";
import { evaluatePolicies } from "./policy.js";
import { generateApiKey, requireScope } from "./auth.js";

const app = Fastify({ logger: true });
await app.register(swagger, { openapi: { info: { title: "SecureDFS API", version: "0.0.1" } } });
await app.register(swaggerUi, { routePrefix: "/docs" });

function parse<T>(schema: { parse(value: unknown): T }, value: unknown): T { return schema.parse(value); }
async function audit(action: string, targetType: string, targetId: string | null, actorType: string, actorId: string, metadata: object = {}, principalId?: string, agentId?: string) {
  await db.auditEvent.create({ data: { action, targetType, targetId, actorType, actorId, metadata, principalId, agentId } });
}

app.get("/health", async () => ({ status: "ok", service: "securedfs-api" }));

app.get("/v1/me", { preHandler: requireScope("agents:read") }, async (request) => {
  const principal = await db.principal.findUniqueOrThrow({ where: { id: request.auth.principalId } });
  return { principal, credential: request.auth };
});

app.get("/v1/agents", { preHandler: requireScope("agents:read") }, async (request) =>
  db.agent.findMany({ where: { principalId: request.auth.principalId }, orderBy: { createdAt: "desc" } })
);

app.post("/v1/agents", { preHandler: requireScope("agents:write") }, async (request, reply) => {
  const body = parse(createAgentSchema, request.body);
  if (body.principalId !== request.auth.principalId) return reply.code(403).send({ error: "cross_tenant_access_denied" });
  const agent = await db.agent.create({ data: body });
  await audit("agent.created", "agent", agent.id, "credential", request.auth.credentialId, {}, body.principalId, agent.id);
  return reply.code(201).send(agent);
});

app.get("/v1/policies", { preHandler: requireScope("policies:read") }, async (request) =>
  db.policy.findMany({ where: { principalId: request.auth.principalId }, orderBy: [{ priority: "asc" }, { createdAt: "desc" }] })
);

app.post("/v1/policies", { preHandler: requireScope("policies:write") }, async (request, reply) => {
  const body = parse(createPolicySchema, request.body);
  if (body.principalId !== request.auth.principalId) return reply.code(403).send({ error: "cross_tenant_access_denied" });
  const policy = await db.policy.create({ data: body });
  await audit("policy.created", "policy", policy.id, "credential", request.auth.credentialId, { effect: body.effect }, body.principalId);
  return reply.code(201).send(policy);
});

app.post("/v1/approval-requests", { preHandler: requireScope("approvals:request") }, async (request, reply) => {
  const body = parse(createApprovalRequestSchema, request.body);
  if (body.principalId !== request.auth.principalId) return reply.code(403).send({ error: "cross_tenant_access_denied" });
  if (request.auth.agentId && request.auth.agentId !== body.agentId) return reply.code(403).send({ error: "agent_identity_mismatch" });
  const agent = await db.agent.findUniqueOrThrow({ where: { id: body.agentId } });
  if (agent.principalId !== body.principalId) return reply.code(403).send({ error: "agent_not_owned_by_principal" });
  const policies = await db.policy.findMany({ where: { principalId: body.principalId, enabled: true } });
  const evaluation = evaluatePolicies(policies, body);
  const { expiresInSeconds, ...requestData } = body;
  const approval = await db.approvalRequest.create({ data: {
    ...requestData, resource: body.resource as Prisma.InputJsonValue,
    status: evaluation.status as RequestStatus, matchedPolicyId: evaluation.matchedPolicyId,
    expiresAt: new Date(Date.now() + expiresInSeconds * 1000)
  } });
  await audit("approval.requested", "approval_request", approval.id, "agent", body.agentId, { status: approval.status, capability: body.capability }, body.principalId, body.agentId);
  return reply.code(201).send(approval);
});

app.get("/v1/approval-requests", { preHandler: requireScope("approvals:read") }, async (request) => {
  const { status } = request.query as { status?: string };
  const validStatus = status && Object.values(RequestStatus).includes(status as RequestStatus) ? status as RequestStatus : undefined;
  return db.approvalRequest.findMany({
    where: { principalId: request.auth.principalId, status: validStatus },
    include: { agent: { select: { id: true, name: true } } }, orderBy: { createdAt: "desc" }, take: 200
  });
});

app.get("/v1/approval-requests/:id", { preHandler: requireScope("approvals:read") }, async (request, reply) => {
  const { id } = request.params as { id: string };
  const approval = await db.approvalRequest.findUniqueOrThrow({ where: { id } });
  if (approval.principalId !== request.auth.principalId) return reply.code(404).send({ error: "not_found" });
  return approval;
});

app.post("/v1/approval-requests/:id/decision", { preHandler: requireScope("approvals:decide") }, async (request, reply) => {
  const { id } = request.params as { id: string };
  const body = parse(decisionSchema, request.body);
  const current = await db.approvalRequest.findUniqueOrThrow({ where: { id } });
  if (current.principalId !== request.auth.principalId) return reply.code(404).send({ error: "not_found" });
  if (current.status !== "PENDING") return reply.code(409).send({ error: "request_not_pending", status: current.status });
  if (current.expiresAt < new Date()) return reply.code(410).send({ error: "request_expired" });
  const updated = await db.approvalRequest.update({ where: { id }, data: {
    status: body.approved ? "APPROVED" : "REJECTED", decidedBy: body.decidedBy,
    decisionNote: body.note, decidedAt: new Date()
  } });
  await audit("approval.decided", "approval_request", id, "human", body.decidedBy, { approved: body.approved }, current.principalId, current.agentId);
  return updated;
});

app.post("/v1/capability-grants", { preHandler: requireScope("grants:issue") }, async (request, reply) => {
  const body = parse(createGrantSchema, request.body);
  const approval = await db.approvalRequest.findUniqueOrThrow({ where: { id: body.approvalRequestId } });
  if (approval.principalId !== request.auth.principalId) return reply.code(404).send({ error: "not_found" });
  if (request.auth.agentId && request.auth.agentId !== approval.agentId) return reply.code(403).send({ error: "agent_identity_mismatch" });
  if (!["ALLOWED", "APPROVED"].includes(approval.status)) return reply.code(403).send({ error: "request_not_authorized", status: approval.status });
  if (approval.expiresAt < new Date()) return reply.code(410).send({ error: "request_expired" });
  const tokenId = randomUUID();
  const expiresAt = new Date(Math.min(Date.now() + body.ttlSeconds * 1000, approval.expiresAt.getTime()));
  const secret = process.env.SDFS_SIGNING_SECRET;
  if (!secret || secret.length < 32) throw new Error("SDFS_SIGNING_SECRET must contain at least 32 characters");
  const token = await new SignJWT({ capability: approval.capability, resource: approval.resource, approval_request_id: approval.id })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" }).setIssuer(process.env.SDFS_ISSUER ?? "securedfs")
    .setSubject(approval.agentId).setAudience("sdfs-capability").setJti(tokenId)
    .setIssuedAt().setExpirationTime(Math.floor(expiresAt.getTime() / 1000)).sign(new TextEncoder().encode(secret));
  const grant = await db.capabilityGrant.create({ data: { approvalRequestId: approval.id, tokenId, expiresAt } });
  await audit("capability.granted", "capability_grant", grant.id, "system", "access", { capability: approval.capability, tokenId }, approval.principalId, approval.agentId);
  return reply.code(201).send({ grant, token });
});

app.post("/v1/providers", { preHandler: requireScope("providers:write") }, async (request, reply) => {
  const body = parse(createProviderSchema, request.body);
  const provider = await db.provider.create({ data: body });
  await audit("provider.created", "provider", provider.id, "provider", provider.id);
  return reply.code(201).send(provider);
});

app.post("/v1/capabilities", { preHandler: requireScope("providers:write") }, async (request, reply) => {
  const body = parse(createCapabilitySchema, request.body);
  const capability = await db.capability.create({ data: {
    ...body,
    inputSchema: body.inputSchema as Prisma.InputJsonValue,
    outputSchema: body.outputSchema as Prisma.InputJsonValue
  } });
  await audit("capability.registered", "capability", capability.id, "provider", body.providerId, { name: body.name });
  return reply.code(201).send(capability);
});

app.get("/v1/discovery", { preHandler: requireScope("providers:read") }, async (request) => {
  const { capability, includeUnavailable } = request.query as { capability?: string; includeUnavailable?: string };
  return db.capability.findMany({
    where: { name: capability ? { contains: capability, mode: "insensitive" } : undefined, availability: includeUnavailable === "true" ? undefined : "ACTIVE" },
    include: { provider: true }, orderBy: { name: "asc" }, take: 100
  });
});

app.get("/v1/audit", { preHandler: requireScope("audit:read") }, async (request) => {
  const { agentId } = request.query as { agentId?: string };
  return db.auditEvent.findMany({ where: { principalId: request.auth.principalId, agentId }, orderBy: { occurredAt: "desc" }, take: 200 });
});

app.get("/v1/credentials", { preHandler: requireScope("credentials:manage") }, async (request) => {
  return db.apiCredential.findMany({
    where: { principalId: request.auth.principalId },
    select: { id: true, name: true, keyPrefix: true, scopes: true, agentId: true, expiresAt: true, lastUsedAt: true, revokedAt: true, createdAt: true },
    orderBy: { createdAt: "desc" }
  });
});

app.post("/v1/credentials", { preHandler: requireScope("credentials:manage") }, async (request, reply) => {
  const body = parse(createCredentialSchema, request.body);
  if (body.agentId) {
    const agent = await db.agent.findUniqueOrThrow({ where: { id: body.agentId } });
    if (agent.principalId !== request.auth.principalId) return reply.code(403).send({ error: "cross_tenant_access_denied" });
  }
  const generated = generateApiKey();
  const credential = await db.apiCredential.create({ data: {
    principalId: request.auth.principalId, agentId: body.agentId, name: body.name,
    scopes: body.scopes, expiresAt: body.expiresAt ? new Date(body.expiresAt) : undefined,
    keyPrefix: generated.prefix, secretHash: generated.secretHash
  } });
  await audit("credential.created", "api_credential", credential.id, "credential", request.auth.credentialId, { scopes: body.scopes, keyPrefix: generated.prefix }, request.auth.principalId, body.agentId);
  return reply.code(201).send({
    credential: { id: credential.id, name: credential.name, keyPrefix: credential.keyPrefix, scopes: credential.scopes, agentId: credential.agentId, expiresAt: credential.expiresAt },
    apiKey: generated.apiKey,
    warning: "This key is shown once and cannot be recovered."
  });
});

app.post("/v1/credentials/:id/revoke", { preHandler: requireScope("credentials:manage") }, async (request, reply) => {
  const { id } = request.params as { id: string };
  const credential = await db.apiCredential.findUniqueOrThrow({ where: { id } });
  if (credential.principalId !== request.auth.principalId) return reply.code(404).send({ error: "not_found" });
  if (credential.id === request.auth.credentialId) return reply.code(409).send({ error: "cannot_revoke_current_credential" });
  const revoked = await db.apiCredential.update({ where: { id }, data: { revokedAt: new Date() } });
  await audit("credential.revoked", "api_credential", id, "credential", request.auth.credentialId, {}, request.auth.principalId, credential.agentId ?? undefined);
  return { id: revoked.id, revokedAt: revoked.revokedAt };
});

app.setErrorHandler((error, _request, reply) => {
  const caught = error as Error & { statusCode?: number };
  if (caught.name === "ZodError") return reply.code(400).send({ error: "invalid_request", details: JSON.parse(caught.message) });
  app.log.error(error);
  return reply.code(caught.statusCode ?? 500).send({ error: "internal_error" });
});

const port = Number(process.env.PORT ?? 4100);
await app.listen({ port, host: process.env.HOST ?? "0.0.0.0" });
