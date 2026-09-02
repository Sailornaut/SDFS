import type { CreateApprovalRequest } from "@sdfs/contracts";

type EvaluatedPolicy = {
  id: string;
  capabilityPattern: string;
  effect: "ALLOW" | "DENY" | "REQUIRE_APPROVAL";
  maxAmountCents: number | null;
  priority: number;
  enabled: boolean;
};

export function matchesCapability(pattern: string, capability: string): boolean {
  if (pattern === "*") return true;
  if (pattern.endsWith(".*")) return capability.startsWith(pattern.slice(0, -1));
  return pattern === capability;
}

export function evaluatePolicies(policies: EvaluatedPolicy[], request: CreateApprovalRequest) {
  const match = policies
    .filter((policy) => policy.enabled)
    .sort((a, b) => a.priority - b.priority)
    .find((policy) => matchesCapability(policy.capabilityPattern, request.capability));

  if (!match) return { status: "PENDING" as const, matchedPolicyId: null };
  if (match.maxAmountCents != null && (request.amountCents ?? 0) > match.maxAmountCents) {
    return { status: "PENDING" as const, matchedPolicyId: match.id };
  }
  const status = match.effect === "ALLOW" ? "ALLOWED" : match.effect === "DENY" ? "DENIED" : "PENDING";
  return { status, matchedPolicyId: match.id };
}
