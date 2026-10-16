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
    <nav className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b bg-white px-6 py-3 shadow-sm">
      <span className="font-mono text-lg font-bold text-brand-dark">PQ·ANON</span>
      <div className="flex gap-4">
        {links.map((l) => (
          <Link
            key={l.href}
            href={l.href}
            className={
              router.pathname === l.href
                ? "font-semibold text-brand-dark"
                : "text-gray-500 hover:text-gray-900"
            }
          >
            {l.label}
          </Link>
        ))}
      </div>
      <button
        onClick={logout}
        className="ml-auto text-sm text-gray-500 hover:text-red-600"
      >
        Sign out
      </button>
    </nav>
  );
}
