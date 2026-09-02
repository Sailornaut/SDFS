import assert from "node:assert/strict";
import test from "node:test";
import { matchesCapability } from "./policy.js";

test("capability matching supports exact and namespace wildcard", () => {
  assert.equal(matchesCapability("github.repository.write", "github.repository.write"), true);
  assert.equal(matchesCapability("github.*", "github.repository.write"), true);
  assert.equal(matchesCapability("github.repository.read", "github.repository.write"), false);
});
