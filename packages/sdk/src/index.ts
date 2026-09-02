export type ApprovalStatus = "ALLOWED" | "DENIED" | "PENDING" | "APPROVED" | "GRANTED" | "REJECTED" | "EXPIRED";

export type ApprovalRequest = {
  id: string;
  principalId: string;
  agentId: string;
  capability: string;
  reason: string;
  resource: Record<string, unknown>;
  status: ApprovalStatus;
  expiresAt: string;
};

export type CapabilityGrant = {
  grant: { id: string; tokenId: string; expiresAt: string };
  token: string;
};

export type SDFSOptions = {
  apiKey: string;
  principalId: string;
  agentId: string;
  baseUrl?: string;
  pollIntervalMs?: number;
};

export class SDFSError extends Error {
  constructor(public status: number, public code: string, message?: string) { super(message ?? code); }
}

export class ApprovalHandle {
  constructor(private client: SDFS, public approval: ApprovalRequest) {}

  async refresh() { this.approval = await this.client.getApproval(this.approval.id); return this; }

  async waitForDecision(options: { timeoutMs?: number; signal?: AbortSignal } = {}) {
    const timeoutMs = options.timeoutMs ?? 15 * 60_000;
    const deadline = Date.now() + timeoutMs;
    while (this.approval.status === "PENDING") {
      if (options.signal?.aborted) throw new DOMException("Polling aborted", "AbortError");
      if (Date.now() >= deadline) throw new SDFSError(408, "approval_timeout");
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(resolve, this.client.pollIntervalMs);
        options.signal?.addEventListener("abort", () => { clearTimeout(timer); reject(new DOMException("Polling aborted", "AbortError")); }, { once: true });
      });
      await this.refresh();
    }
    return this;
  }

  get approved() { return this.approval.status === "ALLOWED" || this.approval.status === "APPROVED"; }

  async redeem(ttlSeconds = 900) {
    if (!this.approved) throw new SDFSError(409, "approval_not_redeemable", `Approval is ${this.approval.status}`);
    const grant = await this.client.redeem(this.approval.id, ttlSeconds);
    this.approval = { ...this.approval, status: "GRANTED" };
    return grant;
  }
}

export class SDFS {
  readonly baseUrl: string;
  readonly pollIntervalMs: number;
  constructor(private options: SDFSOptions) {
    this.baseUrl = (options.baseUrl ?? "http://localhost:4100").replace(/\/$/, "");
    this.pollIntervalMs = options.pollIntervalMs ?? 1500;
  }

  private async call<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: { authorization: `Bearer ${this.options.apiKey}`, "content-type": "application/json", ...init?.headers }
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({})) as { error?: string };
      throw new SDFSError(response.status, body.error ?? "sdfs_request_failed");
    }
    return response.json() as Promise<T>;
  }

  async request(input: { capability: string; reason: string; resource?: Record<string, unknown>; amountCents?: number; expiresInSeconds?: number }) {
    const approval = await this.call<ApprovalRequest>("/v1/approval-requests", { method: "POST", body: JSON.stringify({
      principalId: this.options.principalId, agentId: this.options.agentId,
      resource: input.resource ?? {}, expiresInSeconds: input.expiresInSeconds ?? 900, ...input
    }) });
    return new ApprovalHandle(this, approval);
  }

  getApproval(id: string) { return this.call<ApprovalRequest>(`/v1/approval-requests/${id}`); }

  redeem(approvalRequestId: string, ttlSeconds: number) {
    return this.call<CapabilityGrant>("/v1/capability-grants", { method: "POST", body: JSON.stringify({ approvalRequestId, ttlSeconds }) });
  }
}
