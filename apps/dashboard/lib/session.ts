import "server-only";
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { cookies } from "next/headers";

const COOKIE = "sdfs_session";

function key() {
  const secret = process.env.DASHBOARD_SESSION_SECRET;
  if (!secret || secret.length < 32) throw new Error("DASHBOARD_SESSION_SECRET must contain at least 32 characters");
  return createHash("sha256").update(secret).digest();
}

function encrypt(value: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key(), iv);
  const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString("base64url");
}

function decrypt(value: string) {
  const payload = Buffer.from(value, "base64url");
  const decipher = createDecipheriv("aes-256-gcm", key(), payload.subarray(0, 12));
  decipher.setAuthTag(payload.subarray(12, 28));
  return Buffer.concat([decipher.update(payload.subarray(28)), decipher.final()]).toString("utf8");
}

export async function setSession(apiKey: string) {
  const jar = await cookies();
  jar.set(COOKIE, encrypt(apiKey), { httpOnly: true, sameSite: "strict", secure: process.env.NODE_ENV === "production", path: "/", maxAge: 60 * 60 * 8 });
}

export async function clearSession() { (await cookies()).delete(COOKIE); }

export async function getApiKey() {
  const value = (await cookies()).get(COOKIE)?.value;
  if (!value) return null;
  try { return decrypt(value); } catch { return null; }
}
