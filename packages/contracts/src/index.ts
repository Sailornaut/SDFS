import { z } from "zod";

export const effectSchema = z.enum(["ALLOW", "DENY", "REQUIRE_APPROVAL"]);
export const requestStatusSchema = z.enum(["ALLOWED", "DENIED", "PENDING", "APPROVED", "REJECTED", "EXPIRED"]);

export const createPrincipalSchema = z.object({
  name: z.string().min(1).max(120),
  externalRef: z.string().max(200).optional()
});

export const createAgentSchema = z.object({
  principalId: z.string().cuid(),
  name: z.string().min(1).max(120),
  description: z.string().max(1000).optional()
});

export const createCredentialSchema = z.object({
  name: z.string().min(1).max(120),
  agentId: z.string().cuid().optional(),
  scopes: z.array(z.enum([
    "agents:read", "agents:write", "policies:read", "policies:write",
    "approvals:read", "approvals:request", "approvals:decide",
    "grants:issue", "providers:read", "providers:write", "audit:read",
    "credentials:manage"
  ])).min(1),
  expiresAt: z.iso.datetime().optional()
});

export const createPolicySchema = z.object({
  principalId: z.string().cuid(),
  name: z.string().min(1).max(120),
  capabilityPattern: z.string().min(1).max(200),
  effect: effectSchema,
  maxAmountCents: z.number().int().nonnegative().optional(),
  priority: z.number().int().min(0).max(10000).default(100)
});

export const createApprovalRequestSchema = z.object({
  principalId: z.string().cuid(),
  agentId: z.string().cuid(),
  capability: z.string().min(1).max(200),
  reason: z.string().min(1).max(4000),
  amountCents: z.number().int().nonnegative().optional(),
  resource: z.record(z.string(), z.unknown()).default({}),
  expiresInSeconds: z.number().int().min(60).max(86400).default(900)
});

export const decisionSchema = z.object({
  approved: z.boolean(),
  decidedBy: z.string().min(1).max(200),
  note: z.string().max(2000).optional()
});

export const createGrantSchema = z.object({
  approvalRequestId: z.string().cuid(),
  ttlSeconds: z.number().int().min(30).max(3600).default(900)
});

export const createProviderSchema = z.object({
  name: z.string().min(1).max(120),
  slug: z.string().regex(/^[a-z0-9-]+$/),
  baseUrl: z.string().url(),
  description: z.string().max(1000).optional()
});

export const createCapabilitySchema = z.object({
  providerId: z.string().cuid(),
  name: z.string().min(1).max(200),
  version: z.string().min(1).max(40).default("1.0"),
  description: z.string().max(2000).optional(),
  inputSchema: z.record(z.string(), z.unknown()).default({}),
  outputSchema: z.record(z.string(), z.unknown()).default({}),
  authMethods: z.array(z.string()).default(["sdfs-capability"]),
  availability: z.enum(["ACTIVE", "COMING_SOON", "PAUSED"]).default("ACTIVE")
});

export type CreateApprovalRequest = z.infer<typeof createApprovalRequestSchema>;
