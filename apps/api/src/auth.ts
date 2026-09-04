import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { FastifyReply, FastifyRequest } from "fastify";
import { db } from "@sdfs/db";

export type Scope =
  | "agents:read" | "agents:write" | "policies:read" | "policies:write"
  | "approvals:read" | "approvals:request" | "approvals:decide"
  | "grants:issue" | "grants:introspect" | "grants:consume" | "providers:read" | "providers:write" | "audit:read"
  | "credentials:manage";

export type AuthContext = { credentialId: string; principalId: string; agentId: string | null; scopes: string[] };

declare module "fastify" { interface FastifyRequest { auth: AuthContext } }

export function hashApiKey(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function generateApiKey() {
  const prefix = `sdfs_${randomBytes(6).toString("hex")}`;
  const apiKey = `${prefix}.${randomBytes(32).toString("base64url")}`;
  return { apiKey, prefix, secretHash: hashApiKey(apiKey) };
}

export function hasScope(granted: string[], required: Scope): boolean {
  return granted.includes("*") || granted.includes(required);
}

export async function authenticate(request: FastifyRequest, reply: FastifyReply) {
  const header = request.headers.authorization;
  if (!header?.startsWith("Bearer ")) return reply.code(401).send({ error: "missing_bearer_token" });
  const token = header.slice(7);
  if (!token.startsWith("sdfs_") || !token.includes(".")) return reply.code(401).send({ error: "invalid_bearer_token" });
  const prefix = token.slice(0, token.indexOf("."));
  const credential = await db.apiCredential.findUnique({ where: { keyPrefix: prefix } });
  if (!credential || credential.revokedAt || (credential.expiresAt && credential.expiresAt <= new Date())) {
    return reply.code(401).send({ error: "invalid_or_expired_credential" });
  }
  const actual = Buffer.from(hashApiKey(token), "hex");
  const expected = Buffer.from(credential.secretHash, "hex");
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
    return reply.code(401).send({ error: "invalid_or_expired_credential" });
  }
  request.auth = { credentialId: credential.id, principalId: credential.principalId, agentId: credential.agentId, scopes: credential.scopes };
  void db.apiCredential.update({ where: { id: credential.id }, data: { lastUsedAt: new Date() } }).catch(() => undefined);
}

export function requireScope(scope: Scope) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    await authenticate(request, reply);
    if (reply.sent) return;
    if (!hasScope(request.auth.scopes, scope)) return reply.code(403).send({ error: "insufficient_scope", required: scope });
  };
}
