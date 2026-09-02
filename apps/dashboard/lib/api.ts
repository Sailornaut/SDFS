import "server-only";
import { redirect } from "next/navigation";
import { getApiKey } from "./session";

export async function sdfs<T>(path: string, init?: RequestInit): Promise<T> {
  const apiKey = await getApiKey();
  if (!apiKey) redirect("/login");
  const response = await fetch(`${process.env.SDFS_API_URL ?? "http://localhost:4100"}${path}`, {
    ...init,
    headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}`, ...init?.headers },
    cache: "no-store"
  });
  if (response.status === 401) redirect("/login?expired=1");
  if (!response.ok) throw new Error(`SecureDFS API returned ${response.status}: ${await response.text()}`);
  return response.json() as Promise<T>;
}
