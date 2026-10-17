// The hosted preview: the real web UI pages (web-ui/pages) in one page, over
// the real control plane compiled to WebAssembly (control-plane/wasm_main.go).
import { useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { RouterContext, type PreviewRouter } from "./shims/next-router";
import Home from "../pages/index";
import Login from "../pages/login";
import Dashboard from "../pages/dashboard";
import Devices from "../pages/devices";
import Pay from "../pages/pay";

const pages: Record<string, () => JSX.Element> = {
  "/": Home,
  "/login": Login,
  "/dashboard": Dashboard,
  "/devices": Devices,
  "/pay": Pay,
};

function initialPath(): string {
  const token = location.hash.replace(/^#/, "");
  return pages["/" + token] ? "/" + token : "/";
}

function Shell() {
  const [path, setPath] = useState(initialPath);
  const router = useMemo<PreviewRouter>(() => {
    const go = async (to: string) => {
      const next = pages[to] ? to : "/";
      setPath(next);
      try {
        history.replaceState(null, "", next === "/" ? location.pathname : "#" + next.slice(1));
      } catch {
        /* the frame may refuse; navigation still works */
      }
      window.scrollTo(0, 0);
      return true;
    };
    return { pathname: path, push: go, replace: go };
  }, [path]);
  const Page = pages[path];
  return (
    <RouterContext.Provider value={router}>
      <Page key={path} />
    </RouterContext.Provider>
  );
}

function start() {
  createRoot(document.getElementById("app")!).render(<Shell />);
}

(window as unknown as { shaipStart: () => void }).shaipStart = start;
