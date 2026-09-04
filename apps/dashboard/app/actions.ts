"use server";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { sdfs } from "../lib/api";
import { clearSession } from "../lib/session";

async function decide(formData: FormData, approved: boolean) {
  const id = String(formData.get("id"));
  await sdfs(`/v1/approval-requests/${id}/decision`, { method: "POST", body: JSON.stringify({ approved, decidedBy: "SecureDFS dashboard" }) });
  revalidatePath("/");
}

export async function approve(formData: FormData) { await decide(formData, true); }
export async function deny(formData: FormData) { await decide(formData, false); }

export async function logout() { await clearSession(); redirect("/login"); }

export type CredentialState = { apiKey?: string; error?: string };

export async function createAgentCredential(_previous: CredentialState, formData: FormData): Promise<CredentialState> {
  try {
    const result = await sdfs<{ apiKey: string }>("/v1/credentials", {
      method: "POST",
      body: JSON.stringify({
        name: String(formData.get("name") || "Agent runtime credential"),
        agentId: String(formData.get("agentId")),
        scopes: ["approvals:request", "approvals:read", "grants:issue"]
      })
    });
    revalidatePath("/");
    return { apiKey: result.apiKey };
  } catch (error) { return { error: error instanceof Error ? error.message : "Credential creation failed" }; }
}

export async function revokeCredential(formData: FormData) {
  await sdfs(`/v1/credentials/${String(formData.get("id"))}/revoke`, { method: "POST" });
  revalidatePath("/");
}
