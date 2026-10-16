import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/router";
import Nav from "@/components/Nav";
import { api, getToken } from "@/lib/api";

// A device is listed by its platform label, the day it was enrolled and the
// start of its id: the control plane stores no device names (they often carry
// the owner's name) and no record of when or from where a device connects.
type Device = {
  id: string;
  name: string;
  created_at: string;
  cert_expires: string;
  revoked_at?: string;
};

type Issued = { url: string; expires_at: string };

const dayOf = (iso: string) => iso.slice(0, 10);

export default function Devices() {
  const router = useRouter();
  const [devices, setDevices] = useState<Device[]>([]);
  const [link, setLink] = useState<Issued | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(() => {
    api<Device[]>("/api/devices")
      .then((d) => setDevices(d ?? []))
      .catch((e) => setErr(e.message));
  }, []);

  useEffect(() => {
    if (!getToken()) {
      router.replace("/login");
      return;
    }
    load();
  }, [router, load]);

  const addDevice = async () => {
    setErr(null);
    try {
      setLink(await api<Issued>("/api/enroll/issue", { method: "POST", body: {} }));
    } catch (e) {
      setErr(e instanceof Error ? e.message : "request failed");
    }
  };

  const revoke = async (id: string) => {
    if (!confirm("Revoke this device? It will be refused by every server.")) return;
    try {
      await api(`/api/devices/${id}`, { method: "DELETE" });
      load();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "request failed");
    }
  };

  return (
    <div>
      <Nav />
      <div className="space-y-6 p-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Devices</h1>
          <button onClick={addDevice} className="btn-glass px-4 py-2 text-sm">
            Add a device
          </button>
        </div>
        {err && <div className="text-threat">Error: {err}</div>}
        {link && (
          <div className="max-w-2xl space-y-2 glass p-4 text-sm">
            <div>Open this link on the device you&apos;re adding (it works once, until {link.expires_at.slice(11, 16)} UTC):</div>
            <div className="select-all break-all rounded bg-black/30 p-2 font-mono text-xs text-ink">{link.url}</div>
          </div>
        )}
        {devices.length === 0 ? (
          <div className="text-ink-2">No devices enrolled.</div>
        ) : (
          <div className="max-w-3xl overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="text-xs uppercase text-ink-2">
              <tr>
                <th className="py-2">Device</th>
                <th>Enrolled</th>
                <th>Certificate until</th>
                <th>Id</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.id} className="border-t border-white/10">
                  <td className="py-2">{d.name}</td>
                  <td>{dayOf(d.created_at)}</td>
                  <td>{dayOf(d.cert_expires)}</td>
                  <td className="font-mono text-xs">{d.id.slice(0, 8)}</td>
                  <td className="text-right">
                    {d.revoked_at ? (
                      <span className="text-ink-3">revoked {dayOf(d.revoked_at)}</span>
                    ) : (
                      <button onClick={() => revoke(d.id)} className="text-threat hover:underline">
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </div>
    </div>
  );
}
