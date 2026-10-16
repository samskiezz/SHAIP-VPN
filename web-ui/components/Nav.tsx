import Link from "next/link";
import { useRouter } from "next/router";
import { clearToken } from "@/lib/api";

const links = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/servers", label: "Servers" },
  { href: "/devices", label: "Devices" },
  { href: "/pay", label: "Buy access" },
];

export default function Nav() {
  const router = useRouter();
  const logout = () => {
    clearToken();
    router.push("/login");
  };
  return (
    <nav className="sticky top-0 z-20 flex flex-wrap items-center gap-x-6 gap-y-2 border-b border-white/10 bg-bg-bottom/70 px-6 py-3 backdrop-blur-xl">
      <span className="font-mono text-lg font-bold tracking-tight text-signal">PQ·ANON</span>
      <div className="flex flex-wrap gap-4">
        {links.map((l) => (
          <Link
            key={l.href}
            href={l.href}
            className={
              router.pathname === l.href
                ? "font-semibold text-ink"
                : "text-ink-2 transition-colors hover:text-ink"
            }
          >
            {l.label}
          </Link>
        ))}
      </div>
      <button onClick={logout} className="ml-auto text-sm text-ink-2 transition-colors hover:text-threat">
        Sign out
      </button>
    </nav>
  );
}
