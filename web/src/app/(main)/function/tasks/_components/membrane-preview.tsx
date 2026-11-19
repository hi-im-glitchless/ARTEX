"use client";

import * as React from "react";

import { EyeIcon, Loader2Icon, PlusIcon, XIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { MembranePreview } from "@/lib/types";

// Debounce between the last keystroke and the preview request.
const DEBOUNCE_MS = 500;

type Segment =
  | { kind: "plain"; text: string; key: string }
  | { kind: "replaced"; text: string; key: string; valueKind: string }
  | { kind: "suspicious"; text: string; key: string; term: string };

// segments cuts the aliased text into plain / replaced / suspicious runs. Offsets are UTF-16
// code units (JS string indices), so they slice directly. Overlapping or out-of-range spans
// are skipped rather than trusted.
function segments(p: MembranePreview): Segment[] {
  const marks = [
    ...p.spans.map((s) => ({ start: s.start, end: s.end, kind: "replaced" as const, extra: s.kind })),
    ...p.suspicious.map((s) => ({ start: s.start, end: s.end, kind: "suspicious" as const, extra: s.text })),
  ]
    .filter((m) => m.start >= 0 && m.end > m.start && m.end <= p.aliased.length)
    .sort((a, b) => a.start - b.start || b.end - a.end);
  const out: Segment[] = [];
  let pos = 0;
  for (const m of marks) {
    if (m.start < pos) continue;
    if (m.start > pos) out.push({ kind: "plain", text: p.aliased.slice(pos, m.start), key: `p${pos}` });
    const text = p.aliased.slice(m.start, m.end);
    if (m.kind === "replaced") out.push({ kind: "replaced", text, key: `r${m.start}`, valueKind: m.extra });
    else out.push({ kind: "suspicious", text, key: `s${m.start}`, term: m.extra || text });
    pos = m.end;
  }
  if (pos < p.aliased.length) out.push({ kind: "plain", text: p.aliased.slice(pos), key: `p${pos}` });
  return out;
}

// MembranePreviewPanel: "Preview what the AI sees" for the create-task form (spec §12).
// It sends only the text (description + goal), the linked company ids and the pending
// sensitive terms to POST /api/membrane/preview — a server-side dry run that enrols and
// persists nothing. The text is the operator's own and is never logged here.
export function MembranePreviewPanel({
  text,
  companyIds,
  sensitiveTerms,
  onAddTerm,
  onRemoveTerm,
}: {
  text: string;
  companyIds: number[];
  sensitiveTerms: string[];
  onAddTerm: (term: string) => void;
  onRemoveTerm: (term: string) => void;
}) {
  const [preview, setPreview] = React.useState<MembranePreview | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");
  const seq = React.useRef(0);

  // Stable dependency keys: arrays are new on every parent render.
  const companyKey = companyIds.join(",");
  const termsKey = JSON.stringify(sensitiveTerms);

  React.useEffect(() => {
    const id = ++seq.current;
    if (!text.trim()) {
      setPreview(null);
      setError("");
      setLoading(false);
      return;
    }
    setLoading(true);
    const t = setTimeout(() => {
      const terms = JSON.parse(termsKey) as string[];
      api
        .membranePreview({
          text,
          companyIds: companyKey ? companyKey.split(",").map(Number) : [],
          taskScope: terms.map((value) => ({ kind: "keyword" as const, value })),
        })
        .then((r) => {
          if (id !== seq.current) return; // a newer edit superseded this request
          setPreview(r);
          setError("");
        })
        .catch((e) => {
          if (id !== seq.current) return;
          setPreview(null);
          setError((e as Error).message);
        })
        .finally(() => {
          if (id === seq.current) setLoading(false);
        });
    }, DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [text, companyKey, termsKey]);

  const segs = React.useMemo(() => (preview ? segments(preview) : []), [preview]);
  const lowerTerms = React.useMemo(() => new Set(sensitiveTerms.map((t) => t.toLowerCase())), [sensitiveTerms]);

  return (
    <div className="grid gap-2 rounded-lg border p-3">
      <div className="flex items-center gap-2 font-medium text-sm">
        <EyeIcon className="size-4 text-muted-foreground" />
        Preview what the AI sees
        {loading && <Loader2Icon className="size-3.5 animate-spin text-muted-foreground" />}
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-muted-foreground text-xs">
        <span className="inline-flex items-center gap-1">
          <span className="inline-block size-2.5 rounded-sm bg-emerald-500/40 ring-1 ring-emerald-600/50" />
          replaced with an alias
        </span>
        <span className="inline-flex items-center gap-1">
          <span className="inline-block size-2.5 rounded-sm bg-amber-400/40 ring-1 ring-amber-500/60" />
          looks client-specific but is sent as-is
        </span>
        <span>Description and goal, as the remote model would receive them (dry run; nothing is saved).</span>
      </div>

      {!text.trim() && (
        <p className="text-muted-foreground text-xs">Type a description or goal to see the aliased version.</p>
      )}
      {text.trim() && error && <p className="text-destructive text-xs">Preview unavailable: {error}</p>}
      {text.trim() && !error && preview && (
        <div className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-md bg-muted/40 p-2 font-mono text-xs leading-6">
          {segs.map((s) => {
            if (s.kind === "plain") return <React.Fragment key={s.key}>{s.text}</React.Fragment>;
            if (s.kind === "replaced")
              return (
                <span
                  key={s.key}
                  title={`replaced (${s.valueKind})`}
                  className="rounded-sm bg-emerald-500/20 px-0.5 text-emerald-800 ring-1 ring-emerald-600/40 dark:text-emerald-300"
                >
                  {s.text}
                </span>
              );
            const added = lowerTerms.has(s.term.toLowerCase());
            return (
              <span
                key={s.key}
                className="rounded-sm bg-amber-400/25 px-0.5 text-amber-900 ring-1 ring-amber-500/50 dark:text-amber-200"
              >
                {s.text}
                {!added && (
                  <button
                    type="button"
                    className="ml-1 inline-flex items-center gap-0.5 rounded bg-amber-500/20 px-1 align-middle font-sans text-[10px] leading-4 hover:bg-amber-500/40"
                    title="Add as a task-scope keyword: it is aliased from the first request on"
                    onClick={() => onAddTerm(s.term)}
                  >
                    <PlusIcon className="size-2.5" />
                    Add as sensitive term
                  </button>
                )}
              </span>
            );
          })}
        </div>
      )}

      {sensitiveTerms.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-muted-foreground text-xs">Sensitive terms (saved as task scope keywords):</span>
          {sensitiveTerms.map((t) => (
            <Badge key={t} variant="outline" className="gap-1">
              {t}
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="size-4 p-0"
                aria-label={`Remove ${t}`}
                onClick={() => onRemoveTerm(t)}
              >
                <XIcon className="size-3" />
              </Button>
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}
