"use server";
import { redirect } from "next/navigation";
import { setSession } from "../../lib/session";

export async function login(formData: FormData) {
  const apiKey = String(formData.get("apiKey") ?? "").trim();
  if (!apiKey.startsWith("sdfs_")) redirect("/login?invalid=1");
  const response = await fetch(`${process.env.SDFS_API_URL ?? "http://localhost:4100"}/v1/me`, { headers: { authorization: `Bearer ${apiKey}` }, cache: "no-store" });
  if (!response.ok) redirect("/login?invalid=1");
  await setSession(apiKey);
  redirect("/");
}
