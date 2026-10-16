// next/link for the single-page preview: a real link that navigates in place.
import type { ReactNode } from "react";
import { useRouter } from "./next-router";

export default function Link({ href, className, children }: { href: string; className?: string; children: ReactNode }) {
  const router = useRouter();
  return (
    <a
      href={"#" + href.replace(/^\//, "")}
      className={className}
      onClick={(e) => {
        e.preventDefault();
        router.push(href);
      }}
    >
      {children}
    </a>
  );
}
