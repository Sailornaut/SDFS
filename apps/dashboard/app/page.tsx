import { sdfs } from "../lib/api";
import { decide, logout } from "./actions";
import { CredentialManager } from "./credential-manager";

type Approval = { id: string; capability: string; reason: string; status: string; amountCents: number | null; createdAt: string; expiresAt: string; agent: { name: string } };
type Agent = { id: string; name: string; description: string | null };
type Policy = { id: string; name: string; capabilityPattern: string; effect: string; priority: number };
type Event = { id: string; action: string; actorType: string; occurredAt: string };
type Me = { principal: { name: string } };
type Credential = { id: string; name: string; keyPrefix: string; agentId: string | null; scopes: string[]; revokedAt: string | null; expiresAt: string | null };

const time = (value: string) => new Intl.DateTimeFormat("en", { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }).format(new Date(value));

export default async function Dashboard() {
  const [me, approvals, agents, policies, events, credentials] = await Promise.all([
    sdfs<Me>("/v1/me"), sdfs<Approval[]>("/v1/approval-requests"), sdfs<Agent[]>("/v1/agents"),
    sdfs<Policy[]>("/v1/policies"), sdfs<Event[]>("/v1/audit"), sdfs<Credential[]>("/v1/credentials")
  ]);
  const pending = approvals.filter(item => item.status === "PENDING");
  return <main className="dashboard">
    <header>
      <div><p className="eyebrow">SECUREDFS / APPROVE</p><h1>Good morning, {me.principal.name}</h1><p className="muted">Human authority at the edge of autonomous action.</p></div>
      <form action={logout}><button className="ghost">Lock dashboard</button></form>
    </header>
    <section className="metrics">
      <article><span>Pending</span><strong>{pending.length}</strong><small>awaiting a human</small></article>
      <article><span>Agents</span><strong>{agents.length}</strong><small>registered identities</small></article>
      <article><span>Policies</span><strong>{policies.length}</strong><small>active decision rules</small></article>
      <article><span>Decisions</span><strong>{approvals.filter(a => ["APPROVED", "GRANTED", "REJECTED"].includes(a.status)).length}</strong><small>in current history</small></article>
    </section>
    <section className="grid">
      <div className="panel approvals">
        <div className="panel-title"><div><p className="eyebrow">DECISION QUEUE</p><h2>Pending approvals</h2></div><span className="live">● LIVE</span></div>
        {pending.length === 0 ? <div className="empty"><strong>No action required</strong><p>Policy is handling the quiet work.</p></div> : pending.map(item => <article className="request" key={item.id}>
          <div className="request-top"><span className="agent">{item.agent.name}</span><span>{time(item.createdAt)}</span></div>
          <h3>{item.capability}</h3><p>{item.reason}</p>
          <div className="request-meta"><span>Expires {time(item.expiresAt)}</span>{item.amountCents != null && <span>Limit ${(item.amountCents / 100).toFixed(2)}</span>}</div>
          <form action={decide} className="decision"><input type="hidden" name="id" value={item.id}/><button name="decision" value="deny" className="deny">Deny</button><button name="decision" value="approve">Approve once</button></form>
        </article>)}
      </div>
      <aside>
        <CredentialManager agents={agents} credentials={credentials} />
        <div className="panel"><p className="eyebrow">POLICY POSTURE</p><h2>Rules in force</h2>{policies.slice(0, 6).map(p => <div className="row" key={p.id}><div><strong>{p.name}</strong><small>{p.capabilityPattern}</small></div><span className={`effect ${p.effect.toLowerCase()}`}>{p.effect.replace("REQUIRE_", "")}</span></div>)}</div>
        <div className="panel"><p className="eyebrow">AUDIT STREAM</p><h2>Recent activity</h2>{events.slice(0, 6).map(e => <div className="row event" key={e.id}><div><strong>{e.action}</strong><small>{e.actorType} · {time(e.occurredAt)}</small></div></div>)}</div>
      </aside>
    </section>
  </main>;
}
