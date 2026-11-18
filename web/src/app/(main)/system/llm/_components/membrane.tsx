"use client";

import { ShieldCheckIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import type { LLMProfile, MembraneStatus } from "@/lib/types";
import { cn } from "@/lib/utils";

// Read-only per-profile membrane badge (spec §12, §9.4). Trust is derived from base_url by the
// backend (profile.membrane_required = agent.MembraneRequiredByHost, the provider's own rule):
// only a literal loopback / RFC 1918 / ULA IP or "localhost" is a trusted local endpoint.
// It is not a setting. Under ARTEX_MEMBRANE=off every remote profile is unprotected.
export function ProfileMembraneBadge({ profile, status }: { profile: LLMProfile; status: MembraneStatus | null }) {
  if (profile.membrane_required === undefined) return null; // older backend: say nothing rather than guess
  if (!profile.membrane_required) {
    return (
      <Badge
        variant="outline"
        className="border-sky-500/50 text-sky-700 dark:text-sky-300"
        title="Local endpoint (loopback / private IP / localhost): requests carry real values and are not membraned"
      >
        trusted local
      </Badge>
    );
  }
  if (status?.override) {
    return (
      <Badge
        variant="outline"
        className="border-red-500/60 text-red-600 dark:text-red-400"
        title="Remote endpoint, but ARTEX_MEMBRANE=off is in force: real client data is sent"
      >
        membrane off
      </Badge>
    );
  }
  return (
    <Badge
      variant="outline"
      className="border-emerald-500/50 text-emerald-700 dark:text-emerald-300"
      title="Remote endpoint: every request goes through the identity membrane (aliased), or is refused if the membrane is not initialised"
    >
      membrane on
    </Badge>
  );
}

// One-line global membrane status for the LLM page: loaded, key source and entry count.
// The override / not-initialised states also raise the red banner in the main layout.
export function MembraneStatusLine({ status }: { status: MembraneStatus | null }) {
  if (!status) return null;
  let text: string;
  let tone = "text-muted-foreground";
  if (status.override) {
    text = "Identity membrane disabled by ARTEX_MEMBRANE=off — remote models receive real client data.";
    tone = "text-red-600 dark:text-red-400";
  } else if (!status.enabled) {
    text = `Identity membrane not initialised: ${status.error?.trim() || "reason unknown"} — remote LLM calls are refused.`;
    tone = "text-red-600 dark:text-red-400";
  } else {
    const keys = status.keys_source ? `keys from ${status.keys_source}` : "keys loaded";
    text = `Identity membrane on · ${status.entries} mapping entries · ${keys}`;
  }
  return (
    <div className="grid gap-0.5 text-xs">
      <div className={cn("flex items-center gap-1.5", tone)}>
        <ShieldCheckIcon className="size-3.5 shrink-0" />
        <span>{text}</span>
      </div>
      {status.seed_error && (
        <div className="pl-5 text-amber-600 dark:text-amber-400">
          Last startup seed sync failed: {status.seed_error} (each task syncs again before its requests).
        </div>
      )}
    </div>
  );
}
