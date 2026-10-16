import { useState } from "react";
import { useRouter } from "next/router";
import { api, formatAccount, setToken } from "@/lib/api";

// Accounts are anonymous. Signing up asks for a password and nothing else; the
// server answers with a random account number, which is the login. There is no
// email, so a lost account number cannot be recovered: that is the price of
// the operator not knowing who you are.
export default function Login() {
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [account, setAccount] = useState("");
  const [password, setPassword] = useState("");
  const [created, setCreated] = useState<string | null>(null);
  const [noted, setNoted] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const signIn = async (accountNumber: string) => {
    const { token } = await api<{ token: string }>("/api/auth/login", {
      method: "POST",
      auth: false,
      body: { account_number: accountNumber, password },
    });
    setToken(token);
    router.push("/dashboard");
  };

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      if (mode === "register") {
        const { account_number } = await api<{ account_number: string }>("/api/auth/register", {
          method: "POST",
          auth: false,
          body: { password },
        });
        setCreated(account_number);
      } else {
        await signIn(account);
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : "request failed");
    } finally {
      setBusy(false);
    }
  };

  if (created) {
    return (
      <div className="flex min-h-screen items-center justify-center p-6">
        <div className="w-full max-w-sm space-y-4 rounded-xl border bg-white p-6 shadow-sm">
          <div className="font-mono text-2xl font-bold text-brand-dark">PQ·ANON</div>
          <p className="text-sm text-gray-600">Your account number is your login:</p>
          <div className="select-all rounded bg-gray-100 px-3 py-3 text-center font-mono text-xl tracking-wider">
            {formatAccount(created)}
          </div>
          <p className="text-sm text-gray-600">
            Write it down and keep it with your password. We don&apos;t know who you are, so we
            can&apos;t send it to you or recover it. It is shown only now.
          </p>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={noted} onChange={(e) => setNoted(e.target.checked)} />
            I&apos;ve written it down
          </label>
          {err && <div className="text-sm text-red-600">{err}</div>}
          <button
            disabled={!noted || busy}
            onClick={async () => {
              setBusy(true);
              try {
                await signIn(created);
              } catch (e) {
                setErr(e instanceof Error ? e.message : "request failed");
              } finally {
                setBusy(false);
              }
            }}
            className="w-full rounded bg-brand-dark py-2 font-semibold text-white disabled:opacity-50"
          >
            Continue
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center p-6">
      <form
        onSubmit={submit}
        className="w-full max-w-sm space-y-4 rounded-xl border bg-white p-6 shadow-sm"
      >
        <div className="font-mono text-2xl font-bold text-brand-dark">PQ·ANON</div>
        <p className="text-sm text-gray-500">
          {mode === "login"
            ? "Sign in with your account number"
            : "Create an account. No email or name: you get a random account number."}
        </p>
        {mode === "login" && (
          <input
            required
            inputMode="numeric"
            autoComplete="username"
            placeholder="1234 5678 9012 3456"
            value={account}
            onChange={(e) => setAccount(formatAccount(e.target.value).slice(0, 19))}
            className="w-full rounded border px-3 py-2 font-mono tracking-wider"
          />
        )}
        <input
          type="password"
          required
          minLength={8}
          maxLength={1024}
          autoComplete={mode === "login" ? "current-password" : "new-password"}
          placeholder="password (min 8 chars)"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full rounded border px-3 py-2"
        />
        {err && <div className="text-sm text-red-600">{err}</div>}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded bg-brand-dark py-2 font-semibold text-white disabled:opacity-50"
        >
          {busy ? "…" : mode === "login" ? "Sign in" : "Create account"}
        </button>
        <button
          type="button"
          onClick={() => {
            setErr(null);
            setMode(mode === "login" ? "register" : "login");
          }}
          className="w-full text-sm text-gray-500 hover:text-gray-900"
        >
          {mode === "login" ? "Need an account? Create one" : "Have an account number? Sign in"}
        </button>
      </form>
    </div>
  );
}
