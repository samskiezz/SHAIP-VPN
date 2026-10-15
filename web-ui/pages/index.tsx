import { useEffect } from "react";
import { useRouter } from "next/router";
import { getToken } from "@/lib/api";

export default function Home() {
  const router = useRouter();
  useEffect(() => {
    router.replace(getToken() ? "/dashboard" : "/login");
  }, [router]);
  return <div className="p-6 text-gray-500">Loading…</div>;
}
