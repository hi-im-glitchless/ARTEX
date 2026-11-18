"use client";

import * as React from "react";

import { ShieldAlertIcon, ShieldOffIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { MembraneStatus } from "@/lib/types";

// How often the banner re-reads the membrane status. The state only changes on a
// server restart, so a slow poll is enough to pick up a restart behind a live tab.
const POLL_MS = 60_000;

// Global identity-membrane banner (spec §12), shown above every page:
//   - red when ARTEX_MEMBRANE=off is in force: client data reaches the AI unprotected;
//   - red when the membrane failed to initialise: every remote LLM call is refused, and the
//     operator must see why (keys missing / mismatch, refused override, no database).
// Nothing is shown while the status is unknown (request failed) or the membrane is healthy.
export function MembraneBanner() {
  const [status, setStatus] = React.useState<MembraneStatus | null>(null);

  React.useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .membraneStatus()
        .then((s) => {
          if (alive) setStatus(s);
        })
        .catch(() => {
          // Best effort: an unreachable backend shows its own errors elsewhere.
        });
    void load();
    const t = setInterval(load, POLL_MS);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  if (!status) return null;
  if (status.override) {
    return (
      <div role="alert" className="flex items-center gap-2 bg-red-600 px-4 py-2 font-medium text-sm text-white">
        <ShieldOffIcon className="size-4 shrink-0" />
        <span>Membrane disabled by ARTEX_MEMBRANE=off — client data is sent to the AI unprotected.</span>
      </div>
    );
  }
  if (!status.enabled) {
    return (
      <div role="alert" className="flex items-start gap-2 bg-red-600 px-4 py-2 font-medium text-sm text-white">
        <ShieldAlertIcon className="mt-0.5 size-4 shrink-0" />
        <span className="min-w-0 break-words">
          Membrane not initialised: {status.error?.trim() || "reason unknown"} — remote LLM calls are refused.
        </span>
      </div>
    );
  }
  return null;
}
