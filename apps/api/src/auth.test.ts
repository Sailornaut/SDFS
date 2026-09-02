import assert from "node:assert/strict";
import test from "node:test";
import { generateApiKey, hashApiKey, hasScope } from "./auth.js";

test("generated API keys have stable prefixes and non-reversible hashes", () => {
  const generated = generateApiKey();
  assert.match(generated.apiKey, /^sdfs_[a-f0-9]{12}\.[A-Za-z0-9_-]{40,}$/);
  assert.equal(generated.prefix, generated.apiKey.split(".")[0]);
  assert.equal(generated.secretHash, hashApiKey(generated.apiKey));
  assert.equal(generated.secretHash.includes(generated.apiKey), false);
});

test("scope checks accept exact scope and wildcard only", () => {
  assert.equal(hasScope(["approvals:read"], "approvals:read"), true);
  assert.equal(hasScope(["approvals:read"], "approvals:decide"), false);
  assert.equal(hasScope(["*"], "credentials:manage"), true);
});
