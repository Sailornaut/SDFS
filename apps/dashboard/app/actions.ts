"use server";
import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import { sdfs } from "../lib/api";
import { clearSession } from "../lib/session";

export async function decide(formData: FormData) {
  const id = String(formData.get("id"));
  await sdfs(`/v1/approval-requests/${id}/decision`, { method: "POST", body: JSON.stringify({ approved: formData.get("decision") === "approve", decidedBy: "SecureDFS dashboard" }) });
  revalidatePath("/");
}

export async function logout() { await clearSession(); redirect("/login"); }
