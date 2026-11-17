# Identity Membrane for ARTEX — Design

Date: 2026-11-17 · Status: draft for approval

## 1. Intent

ARTEX runs autonomous pentest agents against client targets. Today every prompt,
tool result and finding is sent **as-is** to the configured LLM — currently the
**Kimi API (Moonshot, China)**, OpenAI Chat Completions format, base URL
`https://api.kimi.com/coding/v1`. There is no DPA with that provider, so client
identity, personal data and credentials must not reach it.

The membrane makes the model work in an **alias universe** (`portal.a1b2c3.example`,
`198.18.4.17`, `ORG-7f2c`, fake-but-usable credentials) while ARTEX, its database,
its UI, its reports and its tools keep working with **real** values.

It is an interim control: a local model will later improve detection (and may
replace the remote model altogether). The design keeps detection pluggable so that
swap is local.

**Proof matters.** The company, clients and auditors need evidence that it works.
So the membrane is built to be *verifiable*: every request is checked before it
leaves, violations are blocked, and per-engagement evidence can be exported.

## 2. Goals, non-goals, anti-goals

Goals
- G1. No **known** client identifier (in-scope domains/IPs, org/brand names,
  operator keywords, emails, usernames, passwords, tokens, cookies, personal data
  detected by pattern) is ever sent to a remote LLM. Enforced by a pre-send leak
  check that blocks.
- G2. Agents keep working: tool calls the model writes in alias-space execute
  against the real target; tool output comes back aliased. No change to how the
  operator writes goals or reads results.
- G3. Covers **every** LLM call ARTEX makes (planner, workers, main agent, goals,
  compaction, cold compactor, chat/custom agents, retester, triager, side questions,
  intercept judge, connection test).
- G4. Verifiable: audit log + exportable per-task evidence report + automated
  contract tests.
- G5. Operator sees what the model will see before a task starts (preview panel)
  and can add missed terms in one click.
- G6. Detection is pluggable (dictionary + patterns now; local-LLM detector later).
  A profile can be marked *trusted* (local model) so the membrane is skipped for it.

Non-goals
- Guaranteeing zero leakage of **unknown** free text (a brand name nobody listed and
  no pattern recognises). Mitigated by the preview panel, flagged in audit, closed
  later by the local-model detector.
- Redacting non-LLM egress in v1: notifications (Telegram/webhook/email), remote MCP
  servers, enrich probes. Listed in §12.
- Encrypting local transcripts / local DB rows that are already real today.

Anti-goals (failure even if it "works")
- A1. The membrane makes agents materially worse at pentesting (e.g. aliasing
  technology names, paths, parameter names, the word `admin`, third-party SaaS
  identities the model needs to reason about).
- A2. A garbled or invented alias causes traffic to a **real** third party or the
  operator's LAN.
- A3. Silent fail-open: membrane enabled but a request leaves un-membraned.
- A4. Breaking prompt caching (non-deterministic aliases → every turn a cache miss).

## 3. How ARTEX works today (what the design builds on)

- **One construction point for all LLM providers**: `agent.Config.NewProvider`
  (`agent/provider.go:274-304`) → `llm.NewProvider`. Callers wrap the result with
  `llmrec.Wrap` (recording) and `bindSideProvider` (`server/server.go:440-449`,
  `575-581`); `llmpool` chains these for failover. So a decorator applied inside
  `NewProvider` sits **under** recording and pooling and covers every call path.
- norma `llm.Provider` = `Stream(ctx, CompletionRequest) iter.Seq2[StreamEvent, error]`
  + `Complete(ctx, CompletionRequest) (Message, string, Usage, error)`.
  `CompletionRequest{System []string, Messages []Message, Tools, ...}`;
  `ContentBlock` carries `Text`, `Thinking`(+`Signature`), tool_use `Input`
  (`json.RawMessage`), tool_result content.
  Stream events: `text_delta`, `thinking_delta`, `tool_use_start` (ToolID/Name/ToolIndex),
  `tool_input_delta` (JSON fragment), `message_delta`, `message_stop`, signatures.
- **Full history is re-sent every turn** → aliasing must be deterministic (A4).
- **Engagement context on ctx**: `taskLLMRuntime.Stream/Complete` set
  `llmrec.WithTaskID` (`server/task_llm.go:305,315`) for planner/worker/main/goals/
  compactor; side questions set it (`server/side_questions.go:433`). Chat, retester,
  triager and other conversations carry only `transcript.WithSessionID` (`conv-<id>`).
- **Where client data enters prompts**: task goal/description (`{{.Goal}}`,
  `graphOverviewData` `agent/tools.go:441`), worker system prompt with full asset JSON
  (`agent/worker.go:450-465`), `task_credentials` with **cleartext passwords** in
  graph_overview every round (`agent/tools_creds.go:92-117`, `agent/tools.go:666`),
  tool results (curl/nmap/HTTP bodies, files), findings, related-task overviews,
  global lessons.
- **Scope data that seeds the dictionary**: `companies` (name), `company_scope`
  (domain/ip/cidr/icp/keyword), `task_scope` (company/root_domain/subdomain/ip/cidr/
  icp/keyword), `assets` (with `company_id`), `task_credentials`, `seed()` host
  parsing of goal/description (`server/server.go:1754`).
- **Hooks**: norma `PreToolUse` can block (and rewrite input); `PostToolUse` cannot
  change output. `guard.Guard` already runs PreToolUse for every tool.
- **Recording**: `llmrec` stores `RequestBody` (structured, above our decorator →
  real) and `RawRequest/RawResponse` captured inside `quotaAwareTransport`
  (below our decorator → exactly what was sent, i.e. aliased).

## 4. Approaches considered

| | Approach | Verdict |
|---|---|---|
| A1 | Rewrite raw HTTP bytes in `quotaAwareTransport` | Rejected: per-wire-format JSON surgery ×3 formats, SSE re-framing with split aliases across frames and JSON escapes. Same coverage as A2, much more fragile. |
| **A2** | **`llm.Provider` decorator inside `Config.NewProvider`** | **Chosen.** Works on structured messages (format-agnostic), sees tool_use input as one value, stream handled at event level, sits under llmrec/pool so all paths are covered. |
| B | Target-side proxy (pentest-cockpit membrane, middlehack) — model and ARTEX live in alias-space, proxy de-aliases on the wire | Rejected for ARTEX: ARTEX's DB/UI/goal are real, client data reaches prompts from many non-traffic sources, and CLI tools (nmap/dig/ssh) carry hosts in argv which an HTTP proxy never sees. |
| C | Off-the-shelf gateway (LiteLLM + Presidio, LLM Guard) | Rejected as primary: generic PII only, no pentest identifiers (scope domains, CIDRs, brand codenames), uncertain tool-call de-anonymisation, extra process to fail open. Presidio-style NER may be added later as a Detector. |

What is **kept from each prior project**:

- From **pentest-cockpit** (`backend/membrane.py`): seeded bijective dictionary,
  alias mint-on-first-sight for new subdomains under a scope root, **reserved
  non-routable aliases** (`.example`), brand→codename inference, typed PII handling,
  fail-closed, per-engagement audit log as DPO evidence, encrypted map at rest.
- From **middlehack** (`middleware/redactor.py`): the two-direction engine over one
  mapping table; **deterministic hash-derived aliases**; **format-preserving fake
  credentials/tokens** the model can actually use; auto-enrolment of secrets by key
  context (cookies, Authorization, token/secret-like keys); literal scan of every
  mapped value thereafter; and its hard-won rules:
  - reverse lookup is **kind-agnostic** (a fake API key reused as a password still
    maps back);
  - literal-scan minimum length 3;
  - domains the **model introduces** itself (e.g. an OAST/XSS exfil host) are
    model-known and pass through;
  - ambiguous usernames that are ordinary words/roles (`admin`, `test`) are not
    literal-scanned as free text;
  - secret-key regex must not match `author` (`auth(?!or)`);
  - the `compare_logs` contract → becomes ARTEX's built-in leak check.

## 5. Architecture

```
            real-space                          alias-space
ARTEX agents ──CompletionRequest──► [ membrane.Provider ] ──► llm provider ──► Kimi
  (DB, UI,                            to_model(request)
   tools)   ◄──Message / events───── to_real(response)   ◄──
                                         │
                       leak check (block) + audit + enrolment
                                         │
                                 membrane.Store (Postgres, encrypted)

Tool calls arrive already de-aliased → tools hit the real target.
Tool results enter the next request → aliased by to_model.
PreToolUse guard blocks any tool input still containing alias-shaped values.
```

New Go package `membrane/`:
- `Store` — mapping table (Postgres) + in-memory index, enrolment, encryption.
- `Engine` — `ToModel(text, ctx) (string, report)` / `ToReal(text) string`,
  structured walkers for `CompletionRequest`, `Message`, JSON inputs.
- `Detector` interface — pluggable span detectors (§7).
- `Provider` — the `llm.Provider` decorator (§8).
- `Guard` — PreToolUse check (§9.2).
- `Audit` — event writer + evidence export (§10).

### 5.1 Placement

`agent.Config.NewProvider` wraps the built provider:
`return membrane.Wrap(prov, store, cfg.MembraneMode)` when the profile is not
trusted. Order becomes: `bindSideProvider(llmrec.Wrap(membrane.Wrap(raw)))`.
Consequences:
- `llmrec.RequestBody`/`ResponseBody` (operator view) stay **real**;
  `RawRequest`/`RawResponse` (wire) are **aliased** = proof of what was sent.
- The connection test (`provider.go:479`) also goes through the membrane.
- The one known bypass of `NewProvider` that sends content — norma's DeepSeek
  web-search backend (`tool/websearch.go:463-520`) — is handled at tool level (§9.3).

### 5.2 One global table (decision)

One global mapping table and one global derivation key, not one map per company.
Each entry records provenance (`company_ids`, `task_ids`) for retention and audit.
The request transform always applies the **whole** table.

Why: aliasing more than necessary is harmless; aliasing less is a leak. A global
table means requests whose engagement cannot be resolved (chat, retester, triager,
cross-task "merge all" runs, global lessons that mention another client) are still
fully covered — no fail-open path from missing context. Aliases are consistent
across tasks of the same client, so cross-task context (related tasks, lessons)
stays coherent.
Accepted trade-off: the provider could notice the same alias recurring across
engagements of the same client. Aliases reveal nothing about the original, so
this is judged acceptable. (Per-company namespaces remain possible later by
salting the derivation with company id.)

Task/engagement id from ctx (`llmrec.TaskIDFrom`, session id) is still captured, but
only for **audit attribution** and for **enrolment provenance**, not for selecting
a map.

## 6. Alias formats (fail-safe by construction — anti-goal A2)

All aliases derive from `HMAC-SHA256(derivation_key, kind || normalised_original)`,
so the same original always yields the same alias (A4), across restarts.

| Kind | Original | Alias | Notes |
|---|---|---|---|
| Root domain (in scope / keyword-bearing) | `acmebank.pt` | `a1b2c3.example` | RFC 2606 reserved TLD: never resolves. Subdomain labels preserved: `portal.acmebank.pt` → `portal.a1b2c3.example`. Labels containing a keyword get the keyword replaced (`acmebank-vpn` → `org-7f2c-vpn`). |
| Third-party domain | `okta.com`, `cloudflare.net` | **unchanged** | Tech identity is needed for pentest reasoning (A1) and does not identify the client. Exception: labels with client keywords (`acmebank.okta.com` → `org-7f2c.okta.com`). |
| Public IPv4 | `185.12.40.17` | `240.a.b.17` | Reserved class-E block `240.0.0.0/4`: never routable, and OS stacks refuse to connect to it, so it fails safe. `198.18.0.0/15` was rejected because Clash/Mihomo fake-IP DNS hands out real addresses there. Allocation is **per /24 block**: each real /24 gets one alias /24, allocated sequentially and persisted, with the last octet preserved. Scope CIDRs wider than /24 are allocated an aligned contiguous alias block **at seed time**. A /24 already allocated before its wider CIDR was seeded keeps its old alias, so history stays stable. |
| Public IPv6 | … | `2001:db8::/32` (documentation prefix) | Same scheme. |
| Private / loopback / link-local / metadata IPs | `10.0.0.5`, `169.254.169.254` | **unchanged** | Needed for SSRF/internal reasoning (A1); not client-identifying on their own. |
| Org / brand / person keywords | `Acme Bank`, `AcmeOnline`, `João Silva` | `ORG-7f2c`, `PRODUCT-19ab`, `PERSON-c3d0` | Case-insensitive; DNS-safe lowercase form `org-7f2c` inside hostnames. Variants inferred (§7.1). |
| Email | `joao.silva@acmebank.pt` | `user-5e1a@a1b2c3.example` | Local part is personal data → aliased too (differs from middlehack). Free-mail domains keep the domain: `u-5e1a@gmail.com`. |
| Username / password / token / cookie / API key | `hunter2`, `sk_live_…` | format-preserving fake (`grksbd6`, `tv_llru_…`) | Same length and character classes (middlehack). The model can use them in requests; they map back exactly. |
| Phone / IBAN / NIF / card number | `+351 912 345 678` | format-preserving digit fake | Reversible (the model may need to submit them, e.g. IDOR on a NIF parameter). Card fakes should stay Luhn-valid (builder). |
| Known secret formats (JWT, AWS key, private key block, `CfDJ8…`) | … | format-preserving fake, or `[PRIVATE_KEY_n]` for key blocks | |

Reverse direction (`ToReal`) is an exact-match table lookup over aliases
(kind-agnostic), plus **derivation rules** so the model can still enumerate
(anti-goal A1). Derivation stays inside enrolled client space by construction:
- **Subdomain under an aliased root**: `dev.a1b2c3.example` → `dev.acmebank.pt`.
  Labels are copied, keyword aliases inside labels are reversed, and the new host
  is enrolled.
- **IP inside an allocated alias /24**: `240.a.b.55` → `real.x.y.55`, enrolled.
- **CIDR argument**: reversed only when it is ≤ /24 inside one allocated block,
  or exactly equal to a seeded scope-CIDR alias block. Anything else is left
  alias-shaped and blocked by the tool guard.
- **JWT**: see §7.2.

Values that are alias-shaped but not derivable (an unknown hash root, an
unallocated `240.x` block, an unknown `ORG-xxxx`) are left untouched. The tool
guard (§9.2) then blocks them.

## 7. Detection (`Detector` interface)

```go
type Span struct{ Start, End int; Kind Kind; Confidence float32 }
type Detector interface { Detect(text string, hint Context) []Span }
```

Pipeline for `ToModel`, in order; longest match wins on overlap:

1. **Dictionary** — Aho-Corasick over every original in the table (case-insensitive
   for domains/keywords, exact for secrets; min length 3; ambiguous-word stoplist).
2. **Structural** —
   - domain-shaped tokens; any host under a known in-scope root is auto-enrolled
     (mint-on-first-sight);
   - IPv4/IPv6 (public → enrol);
   - emails;
   - phone, IBAN, PT NIF, card (Luhn);
   - secrets by **context in text**: JSON keys, `Header: value` lines (`Cookie`,
     `Set-Cookie`, `Authorization`, `X-Api-Key`…), query/form `key=value`, using
     middlehack's key regexes;
   - known secret formats (JWT, AWS, PEM, `CfDJ8`).
3. **Later**: `LocalLLMDetector` (NER over free text), optional Presidio sidecar.

Everything a detector finds is **enrolled before the request is sent** and replaced.
Model-introduced domains (first seen in a model reply, not in any tool output or
scope) are recorded as model-known and never aliased, unless they collide with a
protected root.

### 7.2 Encodings and structured tokens

- Both the transform and the leak check normalise and scan these encodings:
  - URL encoding (`%40`, `+`);
  - JSON `\uXXXX` escapes;
  - HTML entities;
  - `Authorization: Basic` base64 (decoded, `user:pass` aliased, re-encoded).

  A match inside an encoded span is replaced in the same encoding.
- **JWTs keep their structure.**
  - `ToModel`: decode header and payload, alias string claims through the
    engine, re-encode, and replace the signature segment with a format-preserving
    fake. The model can read and tamper with claims (`alg:none`, a changed `sub`).
  - `ToReal`: an exactly known fake JWT maps back to the original. An edited JWT
    has its claims de-aliased, and its signature segment is mapped back if known
    or kept as written. The result is re-encoded.
- **Known limit, stated in the evidence export:** arbitrary base64/hex blobs,
  signed cookies and compressed data are not decoded. Values hidden inside them
  are only caught when the whole blob is a known secret (it is then replaced as
  an opaque fake).

### 7.1 Seeding

Seeded at task launch (`launchTask`, `server/goals.go:28`) and whenever scope,
credentials or companies change:
- company names + `company_scope` (domain/ip/cidr/keyword) of linked companies;
- `task_scope` rows; `assets` with those company ids;
- `task_credentials` (username, password);
- structural detections over goal + description;
- brand-variant inference from root domains and company names (cockpit
  `_infer_terms`: `acmebank.pt` → `acmebank`, `Acme Bank`, `ACME`, `acme-bank`).

The existing `keyword` scope kind is reused for operator "sensitive terms"; no new
concept is added.

## 8. The provider decorator

- **Request** (`to_model`): walk `System[]`, every message's text, thinking,
  tool_use `Input` (walk JSON string values, re-marshal only if changed),
  tool_result content. Tool schemas are static and not rewritten (still leak-checked).
- **Leak check** (§9.1) on the transformed request, then forward.
- **Complete**: de-alias the returned `Message` (text, thinking, tool_use inputs)
  and the returned text string.
- **Stream** (no need to force non-streaming):
  - `text_delta` / `thinking_delta`: pass through a hold-back buffer of
    `maxAliasLen` chars; emit de-aliased text once a prefix cannot be the start of
    an alias; flush on block end / `message_stop`.
  - `tool_input_delta`: buffer per `ToolIndex`; at the next `tool_use_start`,
    `message_delta` or `message_stop`, emit one de-aliased fragment.
  - All other events pass through unchanged and in order.
- **Thinking signatures** (Anthropic format only; Kimi/OpenAI has none): a signed
  thinking block must be replayed byte-exact. Store the aliased thinking text keyed
  by signature hash and replay it verbatim instead of re-aliasing.
- **Errors**: any store/engine error → return an error. Never forward un-membraned
  (A3).

## 9. Enforcement

### 9.1 Pre-send leak check (blocks)

After `to_model`, serialise the request and scan it with the dictionary automaton
for **any original in the table**. A hit means a bug (by construction it should be
impossible) → the request is **blocked**, an audit event with the offending kind
and location (never the value) is written, and the run gets an error.

Unknown-but-suspicious tokens (capitalised multi-word names, domain-shaped tokens
outside known roots in operator-authored text) are **flagged, not blocked**. They
appear in the audit and in the preview.

### 9.2 Tool guard (blocks)

A `PreToolUse` check (added to `guard`): if a tool input still contains an
alias-shaped value that `ToReal` could not resolve — `*.example` with our hash
shape, an IP in `240.0.0.0/4` or `2001:db8::/32`, `ORG-xxxx`/`PERSON-xxxx`, or a
known fake credential — block the call. The model gets: *"unknown alias X — use only names
from your context"*. Combined with the reserved alias ranges, this enforces A2 at
two layers.

### 9.3 web_search

Queries are de-aliased before the tool runs, so they would carry real names to
DuckDuckGo/Brave/Tavily/DeepSeek. In membrane mode, a `PreToolUse` rule blocks
`web_search` inputs containing any table original, with the message *"search for
the technology or CVE, not the target"*.

### 9.4 Fail-closed

ARTEX has no roles, so a UI switch to disable the membrane would let anyone
silently defeat it. Instead, *trusted* is **derived, not set**:
- A profile is trusted only when its base URL host is loopback or a private
  RFC 1918 / ULA address (a local model).
- Every other profile always gets the membrane. The only override is the env var
  `ARTEX_MEMBRANE=off`, which requires host access, writes an audit event at
  startup and shows a red banner in the UI.

If the membrane is required and the store cannot load or decrypt, `NewProvider`
returns an error, so no requests are possible. Status is shown in the UI.

## 10. Proof for company, clients and auditors

1. **Audit events** (`membrane_events`, append-only, hash-chained: each row stores
   the hash of the previous row so tampering is detectable): timestamp, task id,
   session, agent role, profile, direction, counts per kind replaced, enrolments,
   flags, blocks. Never stores originals.
2. **Per-request proof, always on**: each request's audit event stores the SHA-256
   of the exact serialised request handed to the provider and the result of the
   pre-send leak check. This does not depend on LLM recording, so the proof
   exists even with recording off and no real prompt is kept for it.
   **Deep proof, when recording is on**: `llm_records.RawRequest` holds the
   aliased bytes actually sent, and the leak check can be **re-run offline**
   over all records of a task (`artex membrane verify --task N`) → pass/fail
   with counts. This is the middlehack `compare_logs` contract, productised.
   Membrane mode does not force recording on. The evidence export states which
   level of proof the task has.
3. **Evidence export** per task / company (PDF/Markdown + JSON):
   - membrane version/config;
   - totals per kind;
   - number of requests, blocks and flags;
   - offline verification result;
   - sample of model-view excerpts;
   - statement of known limits (§2 non-goals).
   The mapping key is never included.
4. **Contract test suite** in CI: port middlehack's scenario as Go tests, plus
   ARTEX-specific cases (credentials in graph_overview, asset JSON in worker
   system prompt, curl `-v` output with cookies, streamed tool calls with aliases
   split across deltas, kind confusion, model-introduced domain, `admin`/`author`
   false positives). Results are referenced in the evidence export.
5. **Retention**: an explicit **"Destroy membrane key for company"** action purges
   the entries referenced only by that company. It is **refused while any real
   data that can still reach a prompt references the company**: non-deleted tasks
   linked to it, its assets, findings, lessons with its `company_id`, or
   `company_scope` rows. Otherwise un-enrolled originals would later go out in the
   clear. Deleting a company does not purge automatically. The purge is itself an
   audit event.

## 11. Storage & keys

- `membrane_entries`: `id, kind, original_hmac (lookup), original_enc (AES-GCM),
  alias, source (seed|auto|operator|model_known), company_ids[], task_ids[],
  first_seen, last_seen`. Unique on `(kind, original_hmac)`; alias unique.
- `membrane_events` as §10.1.
- Keys: `ARTEX_MEMBRANE_KEY` (encryption) and a derivation key, from env or a 0600
  key file under the data dir. If absent on first start, they are generated and
  stored 0600. Losing the keys makes existing aliases unrecoverable; this is
  documented.
- In-memory index: originals→alias and alias→original maps plus an Aho-Corasick
  automaton, rebuilt incrementally on enrolment, guarded for concurrent agents.

## 12. UI

- **Task create form → "Preview what the AI sees"**: `POST /api/membrane/preview
  {text, companyIds, taskScope}` returns the aliased text with spans:
  - replaced (green);
  - suspicious and unaliased (amber), with **"Add as sensitive term"** → writes a
    `keyword` row to the company or task scope;
  - credentials shown as their fakes.
- **Settings → LLM profile**: read-only badge *membrane on* / *trusted local*
  (derived, §9.4). Global status: store loaded, keys present, entry count, and
  the red banner when `ARTEX_MEMBRANE=off`.
- **Task detail → Membrane tab**: counts, flags, blocks, "verify now", evidence
  export.
- **LLM records view**: toggle *operator view* (RequestBody) / *model view*
  (RawRequest).
- No UI or API lists or looks up mapping entries. ARTEX has no admin role to
  restrict them to.

## 13. Out of scope for v1 (follow-ups)

- Notifications (Telegram/Feishu/DingTalk/WeCom/email/webhook) send finding names
  and asset hosts in plain text: optional "alias notifications" toggle later.
- Remote MCP servers (`mcphttp`) receive real tool args (operator-configured).
- `LocalLLMDetector` and the local-model migration path (G6 hooks are in v1).

## 14. Decisions made in this design (for review)

1. Provider decorator (A2) over raw-HTTP rewrite.
2. One global table and key, not per-company maps.
3. Reserved aliases (`.example`, `240.0.0.0/4` per-/24, `2001:db8::/32`) instead
   of realistic fakes for domains/IPs; format-preserving fakes for credentials/PII
   numbers.
11. `ToReal` derives new subdomains/IPs/narrow CIDRs inside enrolled client space
    (§6). Anything else alias-shaped is blocked.
12. URL/JSON/HTML/Basic-auth encodings and JWT structure are handled. Opaque
    blobs are a stated limit (§7.2).
13. *Trusted* is derived from a local base URL. The override is env-only and
    audited (§9.4).
14. Per-request hash + check result is always-on proof. Raw-byte re-verification
    needs LLM recording (§10.2).
15. Key destruction is refused while real data still references the company
    (§10.5).
4. Third-party and private IPs/domains are not aliased.
5. Email local parts are aliased.
6. Known-original leaks block; suspicious unknowns only flag.
7. Streaming stays supported (event-level hold-back), not forced off.
8. Reuse `keyword` scope kind for sensitive terms.
9. web_search containing originals is blocked in membrane mode.
10. Notifications and remote MCP are out of v1.

## 15. Left to the builder

- Aho-Corasick implementation (library or in-house).
- Exact hash-to-alias encodings and hold-back sizes.
- Migration numbering and schema details beyond §11.
- Brand-variant inference heuristics.
- Luhn-valid card fakes.
- UI styling.
- CLI shape of `artex membrane verify`.
- How evidence PDFs are rendered (reuse `report/` templates where possible).
