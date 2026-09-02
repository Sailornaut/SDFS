import "dotenv/config";
import { db } from "@sdfs/db";
import { generateApiKey } from "./auth.js";

const name = process.argv.slice(2).filter((part) => part !== "--").join(" ") || "SecureDFS owner";
const existing = await db.principal.findFirst({ orderBy: { createdAt: "asc" } });
const principal = existing ?? await db.principal.create({ data: { name } });
const generated = generateApiKey();
await db.apiCredential.create({ data: {
  principalId: principal.id, name: "Owner bootstrap credential",
  keyPrefix: generated.prefix, secretHash: generated.secretHash, scopes: ["*"]
} });
console.log(JSON.stringify({ principalId: principal.id, apiKey: generated.apiKey }, null, 2));
await db.$disconnect();
