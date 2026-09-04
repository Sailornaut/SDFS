import assert from "node:assert/strict";
import test from "node:test";
import { publishApproval, subscribeToApproval } from "./approval-events.js";

test("approval subscribers receive matching events and can disconnect", () => {
  const received: string[] = [];
  const unsubscribe = subscribeToApproval("request-1", approval => received.push(approval.status));
  publishApproval({ id: "request-2", status: "REJECTED" });
  publishApproval({ id: "request-1", status: "APPROVED" });
  unsubscribe();
  publishApproval({ id: "request-1", status: "GRANTED" });
  assert.deepEqual(received, ["APPROVED"]);
});
