"use client";
import { useActionState, useState } from "react";
import { createAgentCredential, revokeCredential, type CredentialState } from "./actions";

type Agent = { id: string; name: string };
type Credential = { id: string; name: string; keyPrefix: string; agentId: string | null; scopes: string[]; revokedAt: string | null; expiresAt: string | null };

export function CredentialManager({ agents, credentials }: { agents: Agent[]; credentials: Credential[] }) {
  const [state, action, pending] = useActionState<CredentialState, FormData>(createAgentCredential, {});
  const [copied, setCopied] = useState(false);
  return <div className="panel credentials">
    <p className="eyebrow">AGENT ACCESS</p><h2>Runtime credentials</h2>
    {state.apiKey && <div className="secret-once"><strong>Copy this key now</strong><code>{state.apiKey}</code><button type="button" onClick={async () => { await navigator.clipboard.writeText(state.apiKey!); setCopied(true); }}>{copied ? "Copied" : "Copy credential"}</button><small>It cannot be recovered after this view.</small></div>}
    {state.error && <p className="error">{state.error}</p>}
    {agents.length > 0 && <form action={action} className="credential-form">
      <input name="name" placeholder="Credential name" defaultValue="Deployment agent runtime" required />
      <select name="agentId" required defaultValue=""><option value="" disabled>Select an agent</option>{agents.map(agent => <option key={agent.id} value={agent.id}>{agent.name}</option>)}</select>
      <small>Scopes: request/read approvals, issue grants</small>
      <button disabled={pending}>{pending ? "Creating…" : "Create agent credential"}</button>
    </form>}
    <div className="credential-list">{credentials.filter(item => item.agentId).slice(0, 8).map(item => <div className="row" key={item.id}><div><strong>{item.name}</strong><small>{item.keyPrefix} · {item.revokedAt ? "revoked" : "active"}</small></div>{!item.revokedAt && <form action={revokeCredential}><input type="hidden" name="id" value={item.id}/><button className="tiny deny">Revoke</button></form>}</div>)}</div>
  </div>;
}
