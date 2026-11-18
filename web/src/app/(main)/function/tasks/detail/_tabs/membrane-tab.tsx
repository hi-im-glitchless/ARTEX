"use client";

import * as React from "react";

import {
  ChevronLeftIcon,
  ChevronRightIcon,
  DownloadIcon,
  Loader2Icon,
  RefreshCwIcon,
  ShieldCheckIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { api } from "@/lib/api";
import type { MembraneEvent, MembraneVerifyResult } from "@/lib/types";
import { cn } from "@/lib/utils";

const PAGE_SIZE = 25;

function fmtTime(ts: string) {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts : d.toLocaleString();
}

// "domain 3 · org 1" — kinds and counts only; the audit log never holds originals.
function fmtCounts(c: Record<string, number> | null): string {
  if (!c) return "";
  return Object.entries(c)
    .filter(([, n]) => n > 0)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, n]) => `${k} ${n}`)
    .join(" · ");
}

const RESULT_STYLE: Record<MembraneVerifyResult["result"], { label: string; cls: string }> = {
  pass: { label: "Pass", cls: "border-emerald-500/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300" },
  fail: { label: "Fail", cls: "border-red-500/50 bg-red-500/10 text-red-700 dark:text-red-300" },
  inconclusive: {
    label: "Inconclusive",
    cls: "border-amber-500/50 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  },
};

function Stat({ label, value, warn }: { label: string; value: React.ReactNode; warn?: boolean }) {
  return (
    <div className="rounded-md border px-2.5 py-1.5">
      <div className="text-[11px] text-muted-foreground">{label}</div>
      <div className={cn("font-medium font-mono text-sm", warn && "text-red-600 dark:text-red-400")}>{value}</div>
    </div>
  );
}

function VerifyPanel({ result }: { result: MembraneVerifyResult }) {
  const style = RESULT_STYLE[result.result] ?? RESULT_STYLE.inconclusive;
  const failedKinds = fmtCounts(result.failed_kinds);
  const failedIDs = result.failed_ids ?? [];
  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="outline" className={cn("text-sm", style.cls)}>
          {style.label}
        </Badge>
        {result.reason && <span className="text-sm">{result.reason}</span>}
      </div>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-6">
        <Stat label="Records re-scanned" value={result.checked} />
        <Stat label="Failed" value={result.failed} warn={result.failed > 0} />
        <Stat label="Forwarded requests" value={result.forwarded} />
        <Stat label="Paired / unpaired" value={`${result.paired} / ${result.unpaired}`} />
        <Stat label="Blocked records" value={result.blocked} />
        <Stat label="Unmembraned records" value={result.unmembraned} />
        <Stat label="Records without raw bytes" value={result.no_raw} />
        <Stat
          label="Audit chain"
          value={result.chain_ok ? "intact" : `broken at #${result.chain_first_bad_id ?? "?"}`}
          warn={!result.chain_ok}
        />
      </div>
      {(failedKinds || failedIDs.length > 0) && (
        <div className="text-sm">
          {failedKinds && (
            <div>
              <span className="text-muted-foreground">Failed kinds: </span>
              <span className="font-mono">{failedKinds}</span>
            </div>
          )}
          {failedIDs.length > 0 && (
            <div>
              <span className="text-muted-foreground">Failed LLM record ids: </span>
              <span className="font-mono">{failedIDs.join(", ")}</span>
            </div>
          )}
        </div>
      )}
      {result.note && <p className="text-muted-foreground text-xs">{result.note}</p>}
    </div>
  );
}

// Membrane tab (spec §12): the task's membrane audit events (counts, flags, blocks), an
// on-demand re-verification of the recorded wire bytes, and the evidence export. It never
// shows or looks up mapping entries.
export function MembraneTab({ taskId }: { taskId: string }) {
  const [page, setPage] = React.useState(1);
  const [events, setEvents] = React.useState<MembraneEvent[] | null>(null);
  const [total, setTotal] = React.useState(0);
  const [error, setError] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [reload, setReload] = React.useState(0);
  const [verifying, setVerifying] = React.useState(false);
  const [verify, setVerify] = React.useState<MembraneVerifyResult | null>(null);
  const [verifyError, setVerifyError] = React.useState("");
  const [exporting, setExporting] = React.useState<"" | "md" | "json">("");

  // biome-ignore lint/correctness/useExhaustiveDependencies: reload is a manual refetch trigger
  React.useEffect(() => {
    let alive = true;
    setLoading(true);
    api
      .membraneEvents(taskId, page, PAGE_SIZE)
      .then((r) => {
        if (!alive) return;
        setEvents(r.events);
        setTotal(r.total ?? 0);
        setError("");
      })
      .catch((e) => {
        if (alive) setError((e as Error).message);
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [taskId, page, reload]);

  async function runVerify() {
    setVerifying(true);
    setVerifyError("");
    try {
      setVerify(await api.membraneVerify(taskId));
    } catch (e) {
      setVerify(null);
      setVerifyError((e as Error).message);
    } finally {
      setVerifying(false);
    }
  }

  async function exportEvidence(format: "md" | "json") {
    setExporting(format);
    try {
      await api.membraneEvidence(taskId, format);
    } catch (e) {
      toast.error(`Evidence export failed: ${(e as Error).message}`);
    } finally {
      setExporting("");
    }
  }

  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="grid gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheckIcon className="size-4" />
            Verification &amp; evidence
          </CardTitle>
          <CardDescription>
            Verify re-scans the bytes recorded as sent to remote models for this task against the current membrane
            dictionary and checks the audit hash chain. The export holds counts, kinds and hashes only — no client
            values and no mapping.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" onClick={runVerify} disabled={verifying}>
              {verifying ? <Loader2Icon className="animate-spin" /> : <ShieldCheckIcon />}
              Verify now
            </Button>
            <Button size="sm" variant="outline" onClick={() => exportEvidence("md")} disabled={exporting !== ""}>
              {exporting === "md" ? <Loader2Icon className="animate-spin" /> : <DownloadIcon />}
              Export evidence (Markdown)
            </Button>
            <Button size="sm" variant="outline" onClick={() => exportEvidence("json")} disabled={exporting !== ""}>
              {exporting === "json" ? <Loader2Icon className="animate-spin" /> : <DownloadIcon />}
              Export evidence (JSON)
            </Button>
          </div>
          {verifyError && <p className="text-destructive text-sm">Verify failed: {verifyError}</p>}
          {verify && <VerifyPanel result={verify} />}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            Membrane events
            <Badge variant="secondary">{total}</Badge>
            <Button
              size="icon"
              variant="ghost"
              className="ml-auto size-7"
              aria-label="Refresh events"
              onClick={() => setReload((n) => n + 1)}
              disabled={loading}
            >
              <RefreshCwIcon className={cn(loading && "animate-spin")} />
            </Button>
          </CardTitle>
          <CardDescription>
            One row per membrane decision, newest first: what was aliased (counts by kind), new values enrolled, flags,
            and blocked requests.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3">
          {error && <p className="text-destructive text-sm">{error}</p>}
          {events === null && !error && <Skeleton className="h-24 w-full" />}
          {events !== null && events.length === 0 && (
            <Empty>
              <EmptyHeader>
                <EmptyTitle>No membrane events</EmptyTitle>
                <EmptyDescription>
                  This task has not sent anything through the membrane yet (or ran only on trusted local models).
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          )}
          {events !== null && events.length > 0 && (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Direction</TableHead>
                    <TableHead>Role</TableHead>
                    <TableHead>Profile</TableHead>
                    <TableHead>Aliased (by kind)</TableHead>
                    <TableHead className="text-right">Enrolled</TableHead>
                    <TableHead>Flags</TableHead>
                    <TableHead>Blocked</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {events.map((ev) => (
                    <TableRow key={ev.id} className={cn(ev.blocked && "bg-red-500/5")}>
                      <TableCell className="whitespace-nowrap text-xs">{fmtTime(ev.ts)}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{ev.direction}</Badge>
                      </TableCell>
                      <TableCell className="text-xs">{ev.role || "—"}</TableCell>
                      <TableCell className="max-w-40 truncate text-xs" title={ev.profile}>
                        {ev.profile || "—"}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{fmtCounts(ev.counts) || "—"}</TableCell>
                      <TableCell className="text-right font-mono text-xs">{ev.enrolled}</TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {(ev.flags ?? []).map((f) => (
                            <Badge key={f} variant="secondary" className="font-mono text-[10px]">
                              {f}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell className="text-xs">
                        {ev.blocked ? (
                          <span className="text-red-600 dark:text-red-400">
                            blocked{ev.block_reason ? `: ${ev.block_reason}` : ""}
                          </span>
                        ) : (
                          <span className="text-muted-foreground">—</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
          {total > PAGE_SIZE && (
            <div className="flex items-center justify-end gap-2 text-muted-foreground text-xs">
              <span>
                Page {page} / {pages}
              </span>
              <Button
                size="icon"
                variant="outline"
                className="size-7"
                aria-label="Previous page"
                disabled={page <= 1 || loading}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                <ChevronLeftIcon />
              </Button>
              <Button
                size="icon"
                variant="outline"
                className="size-7"
                aria-label="Next page"
                disabled={page >= pages || loading}
                onClick={() => setPage((p) => Math.min(pages, p + 1))}
              >
                <ChevronRightIcon />
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
