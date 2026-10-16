// next/router for the single-page preview: the same useRouter() the pages
// call (pathname, push, replace), backed by the preview shell's state.
import { createContext, useContext } from "react";

export type PreviewRouter = {
  pathname: string;
  push: (path: string) => Promise<boolean>;
  replace: (path: string) => Promise<boolean>;
};

export const RouterContext = createContext<PreviewRouter | null>(null);

export function useRouter(): PreviewRouter {
  const r = useContext(RouterContext);
  if (!r) throw new Error("useRouter outside the preview shell");
  return r;
}
