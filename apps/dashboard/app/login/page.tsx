import { login } from "./actions";

export default async function Login({ searchParams }: { searchParams: Promise<{ invalid?: string; expired?: string }> }) {
  const params = await searchParams;
  return <main className="login-shell">
    <section className="login-card">
      <div className="mark">S</div>
      <p className="eyebrow">SECUREDFS</p>
      <h1>Agent control plane</h1>
      <p className="muted">Authenticate with a principal credential carrying dashboard scopes.</p>
      {(params.invalid || params.expired) && <p className="error">{params.expired ? "Your session credential expired." : "That credential was not accepted."}</p>}
      <form action={login}>
        <label htmlFor="apiKey">API credential</label>
        <input id="apiKey" name="apiKey" type="password" placeholder="sdfs_…" required autoFocus autoComplete="off" />
        <button type="submit">Enter control plane</button>
      </form>
      <p className="fine">Credentials are encrypted into an HTTP-only session cookie and are never available to browser JavaScript.</p>
    </section>
  </main>;
}
