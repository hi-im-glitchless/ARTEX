# Identity Membrane Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every remote LLM request ARTEX makes is rewritten into an alias universe
(and every reply back to real values), with a blocking pre-send leak check,
hash-chained audit, and exportable evidence.

**Architecture:** A new `membrane/` package holds the mapping store, detectors,
engine (`ToModel`/`ToReal`), an `llm.Provider` decorator and a tool guard.
`agent.Config.NewProvider` wraps every non-local provider with the decorator,
under `llmrec`/`llmpool`, so all call paths are covered. The rest of ARTEX stays
in real values.

**Tech Stack:** Go 1.26, norma v0.4.4 (`github.com/Autumn-27/norma`, replaced by
BaaRai/Norma), PostgreSQL (schema in `db/schema.sql`, executed idempotently at
startup), Next.js UI in `web/`.

**Spec:** `docs/superpowers/specs/2026-11-17-identity-membrane-design.md`. Read it
first. Section numbers (§) below refer to it.

## Global Constraints

- Domain root alias: `<6 lowercase hex>.example`; subdomain labels preserved.
- Public IPv4 alias block `240.0.0.0/4`, allocated per real /24, last octet
  preserved. Public IPv6 alias block `2001:db8::/32`.
- Not aliased: private (RFC 1918, `100.64.0.0/10`), loopback, link-local
  (incl. `169.254.169.254`), ULA IPs; third-party domains without a client
  keyword in a label.
- Keyword aliases: `ORG-xxxx`, `PRODUCT-xxxx`, `PERSON-xxxx` (4 lowercase hex);
  DNS-safe form inside hostnames is the lowercase variant (`org-xxxx`).
- Email alias: `user-xxxx@<domain alias>`; free-mail domains keep their domain
  (`u-xxxx@gmail.com`).
- All deterministic aliases: `HMAC-SHA256(derivationKey, kind+"\x00"+normalised)`.
- Literal-scan minimum length 3. Ambiguous-word stoplist includes at least
  `admin, root, test, user, guest, demo, api, www, mail`. The secret-key regex
  uses `auth(?!or)`. Go has no lookahead, so implement it as a post-match check.
- Reverse lookup is kind-agnostic.
- Membrane errors never fall back to sending un-membraned (fail closed).
- Audit and evidence never contain originals.
- Env: `ARTEX_MEMBRANE_KEY` (base64 32-byte AES key), `ARTEX_MEMBRANE_HMAC_KEY`
  (base64 32 bytes). If both are absent, generate them into
  `<dataDir>/membrane.keys` (0600). `ARTEX_MEMBRANE=off` is the only override.
- Tests that need Postgres follow the existing package pattern: skip when
  `db.DSN()` is unavailable, and use `db.SuffixTestDatabase("<pkg>")` plus the
  advisory lock in `TestMain`.

## Review Focus

1. A streamed reply where an alias is split across two `text_delta` or
   `tool_input_delta` events must still reach the harness de-aliased, with event
   order unchanged. Pinned in Task 7.
2. Tool output containing the same secret in raw, URL-encoded and JSON-escaped
   forms must leave no original in the request. Pinned in Task 5.
3. Concurrent workers enrolling the same new subdomain at once must produce one
   alias and no unique-constraint error. Pinned in Task 3.
4. Real `240.x`/`.example` values that already appear in target output must not
   be mistaken for derivable aliases: they are enrolled and aliased like any
   other value. Pinned in Task 5.
5. A request built before an IP's wider scope CIDR was seeded, and re-sent
   afterwards, must produce byte-identical aliases (prompt-cache stability).
   Pinned in Task 3.

---

### Task 1: Alias derivation primitives

**Files:**
- Create: `membrane/kind.go`, `membrane/alias.go`
- Test: `membrane/alias_test.go`

**Interfaces:**
- Produces:
  - `type Kind string` with constants `KindDomain, KindIPv4, KindIPv6,
    KindEmail, KindOrg, KindProduct, KindPerson, KindUsername, KindPassword,
    KindToken, KindPhone, KindIBAN, KindNIF, KindCard, KindPrivateKey`.
  - `type Deriver struct{ key []byte }` and `NewDeriver(key []byte) *Deriver`.
  - `(*Deriver).RootDomain(root string) string`, which returns `"a1b2c3.example"`.
  - `(*Deriver).Keyword(kind Kind, term string) string`, which returns
    `"ORG-7f2c"`.
  - `(*Deriver).EmailLocal(local string) string`, which returns `"user-5e1a"`.
  - `(*Deriver).FormatPreserving(kind Kind, original string) string`.
  - `(*Deriver).IPv6(ip netip.Addr) netip.Addr`.

- [ ] **Step 1: Write failing tests:**
  - `TestRootDomainDeterministic`: same input gives same output; it matches
    `^[0-9a-f]{6}\.example$`; it is case-insensitive (`AcmeBank.PT` equals
    `acmebank.pt`).
  - `TestKeywordShape`: `ORG-[0-9a-f]{4}`.
  - `TestFormatPreserving`: `"hunter2"` gives a 7-char result with 6 lowercase
    letters and 1 digit in the same positions; `"Pa$$w0rd!"` keeps symbol
    positions and symbols; the result differs from the input; a different key
    gives a different result.
  - `TestFormatPreservingCardLuhn`: a 16-digit Luhn-valid input gives a Luhn-valid
    16-digit output.
  - `TestIPv6InDocPrefix`: the output is inside `2001:db8::/32`.
- [ ] **Step 2:** `go test ./membrane/ -run 'TestRootDomain|TestKeyword|TestFormatPreserving|TestIPv6'` → FAIL (undefined).
- [ ] **Step 3: Implement.** Use HMAC-SHA256 as the seed of a
  `math/rand/v2.ChaCha8` stream for character-class substitution (port of
  middlehack `_class_preserving`). Keyword collisions on 4 hex chars are resolved
  by the store (Task 3), not here.
- [ ] **Step 4:** Run the same command → PASS.
- [ ] **Step 5: Commit** `feat(membrane): deterministic alias derivation`.

### Task 2: Persistence schema and DB access

**Files:**
- Modify: `db/schema.sql` (append section "Membrane")
- Create: `db/membrane.go`
- Test: `db/membrane_test.go`

**Interfaces:**
- Produces, all on `*db.DB`:
  - `type MembraneEntry struct{ ID int64; Kind, OriginalHMAC string;
    OriginalEnc []byte; Alias, Source string; CompanyIDs, TaskIDs []int64;
    FirstSeen, LastSeen time.Time }`
  - `InsertMembraneEntry(e *MembraneEntry) (MembraneEntry, error)`. On conflict
    `(kind, original_hmac)`, return the existing row and merge the provenance
    arrays.
  - `ListMembraneEntries() ([]MembraneEntry, error)`
  - `AllocateMembraneBlock(realPrefix string, bits int) (aliasPrefix string, err error)`.
    The table `membrane_ip_blocks(real_prefix PK, alias_prefix UNIQUE, bits)`
    allocates sequentially from `240.0.0.0`, aligned to `bits`, and is idempotent
    per `real_prefix`.
  - `ListMembraneBlocks() ([]MembraneBlock, error)`
  - `AppendMembraneEvent(ev *MembraneEvent) error`, where `MembraneEvent{ID int64;
    TS time.Time; TaskID, Session, Role, Profile, Direction string;
    Counts map[string]int; Enrolled int; Flags []string; Blocked bool;
    BlockReason, RequestSHA256, PrevHash, Hash string}`. Insert under
    `pg_advisory_xact_lock(7337741099)`: read the last hash, then set
    `Hash = sha256(PrevHash || canonical JSON of the event without Hash)`.
  - `ListMembraneEvents(taskID string, page, size int) ([]MembraneEvent, int, error)`
  - `VerifyMembraneChain() (ok bool, firstBadID int64, err error)`
  - `PurgeMembraneCompany(companyID int64) (purged int, err error)`. Deletes the
    entries whose `company_ids = {companyID}` and whose `task_ids` all belong to
    that company; removes `companyID` from the rest.
  - `MembraneCompanyReferences(companyID int64) (map[string]int, error)`. Counts
    non-deleted linked tasks, assets, findings via those tasks, lessons with
    `company_id`, and `company_scope` rows.

- [ ] **Step 1: Write failing tests:**
  - `TestMembraneEntryUpsertMergesProvenance`.
  - `TestAllocateBlockIdempotentAndAligned`: the same /24 twice gives the same
    alias; a /22 allocation is 4-aligned; two different /24s get distinct aliases.
  - `TestEventChain`: append 3 events; `VerifyMembraneChain` is ok; tamper with
    row 2 via SQL; the check reports `firstBadID == row2`.
  - `TestPurgeRules`: an entry shared by two companies survives with its
    provenance reduced.
- [ ] **Step 2:** `go test ./db/ -run Membrane` → FAIL.
- [ ] **Step 3: Implement.** Use `CREATE TABLE IF NOT EXISTS` plus indexes in
  `schema.sql`. Make `membrane_events` append-only: no UPDATE or DELETE paths in
  Go.
- [ ] **Step 4:** Run the same command → PASS.
- [ ] **Step 5: Commit** `feat(db): membrane tables and hash-chained events`.

### Task 3: Store: encrypted in-memory index and enrolment

**Files:**
- Create: `membrane/store.go`, `membrane/keys.go`, `membrane/automaton.go`
- Test: `membrane/store_test.go`

**Interfaces:**
- Consumes: Task 1 `Deriver`, and Task 2 methods through the interface below.
- Produces:
  - `type Persistence interface` with the Task 2 methods it uses (`InsertMembraneEntry`,
    `ListMembraneEntries`, `AllocateMembraneBlock`, `ListMembraneBlocks`).
    `*db.DB` satisfies it.
  - `LoadKeys(dataDir string) (encKey, hmacKey []byte, err error)`: env vars
    first, then the 0600 file, generated if missing.
  - `OpenStore(p Persistence, encKey, hmacKey []byte) (*Store, error)`: decrypts
    all entries; any decrypt failure is an error.
  - `(*Store).Enroll(kind Kind, original string, prov Provenance) (alias string, err error)`
  - `(*Store).AliasFor(original string) (alias string, kind Kind, ok bool)`
  - `(*Store).OriginalFor(alias string) (original string, kind Kind, ok bool)`, kind-agnostic.
  - `(*Store).IPv4Alias(ip netip.Addr, prov Provenance) (netip.Addr, error)`
  - `(*Store).SeedCIDR(p netip.Prefix, prov Provenance) error`
  - `(*Store).IPv4Real(alias netip.Addr) (netip.Addr, bool)`
  - `(*Store).CIDRReal(alias netip.Prefix) (netip.Prefix, bool)`
  - `(*Store).Dictionary() *Automaton`, a snapshot that is safe for concurrent
    reads.
  - `(*Store).MarkModelKnown(domain string)` and `(*Store).IsModelKnown(domain string) bool`
  - `(*Store).Roots() []string`: real in-scope roots, used by detectors.
  - `type Provenance struct{ CompanyIDs []int64; TaskIDs []int64; Source string }`

- [ ] **Step 1: Write failing tests** using an in-memory fake `Persistence`:
  - `TestEnrollIdempotent`.
  - `TestEnrollConcurrent`: 50 goroutines enrol the same subdomain; there is
    exactly one alias and no error.
  - `TestKeywordCollisionRehash`: force a 4-hex collision via a stub deriver;
    the second term gets a distinct alias.
  - `TestIPv4BlockPreservesLastOctet`.
  - `TestSeedCIDRAfterIPKeepsOldAlias`: enrol `185.12.40.17`, then seed
    `185.12.40.0/22`; `IPv4Alias(185.12.40.17)` is unchanged, and
    `185.12.41.5` maps into the new aligned block.
  - `TestOpenStoreFailsOnWrongKey`.
  - `TestAutomatonCaseInsensitiveDomainsExactSecrets`.
- [ ] **Step 2:** `go test ./membrane/ -run TestEnroll\|TestKeyword\|TestIPv4\|TestSeedCIDR\|TestOpenStore\|TestAutomaton` → FAIL.
- [ ] **Step 3: Implement.**
  - Encrypt originals with AES-256-GCM; `original_hmac` is
    `HMAC(hmacKey, kind+normalised)`.
  - The automaton is an in-house Aho-Corasick over byte-lowered patterns, with a
    per-pattern `caseSensitive` flag, rebuilt copy-on-write on enrolment and
    guarded by a mutex.
  - Domain normalisation: lowercase, trailing dot stripped, punycode via
    `golang.org/x/net/idna`.
- [ ] **Step 4:** Run the same command → PASS (with `-race`).
- [ ] **Step 5: Commit** `feat(membrane): encrypted store with enrolment and IP blocks`.

### Task 4: Detectors

**Files:**
- Create: `membrane/detect.go` (interface and pipeline), `membrane/detect_struct.go`
  (structural detectors), `membrane/encodings.go` (decode views)
- Test: `membrane/detect_test.go`

**Interfaces:**
- Consumes: `*Store` (`Roots`, `Dictionary`, `IsModelKnown`).
- Produces:
  - `type Span struct{ Start, End int; Kind Kind; Value string; Encoding Encoding }`
  - `type Encoding int` with constants `EncRaw, EncURL, EncJSONEscape,
    EncHTMLEntity, EncBasicAuth`.
  - `type Detector interface{ Detect(text string) []Span }`
  - `func NewPipeline(s *Store, extra ...Detector) *Pipeline`
  - `(*Pipeline).Detect(text string) []Span`: non-overlapping spans, longest
    match wins, ordered dictionary → structural → extra.

- [ ] **Step 1: Write failing tests** (middlehack cases ported):
  - `TestDetectSubdomainUnderRoot`.
  - `TestDetectThirdPartyIgnored`: `cdn.cloudflare.net` gives no span;
    `acmebank.okta.com` gives a keyword span only on `acmebank`.
  - `TestDetectPrivateIPIgnored`, `TestDetectPublicIP`.
  - `TestDetectEmail`.
  - `TestDetectPhonePT` (`+351 912 345 678`), `TestDetectIBAN`, `TestDetectNIFChecksum`,
    `TestDetectCardLuhnOnly`.
  - `TestDetectSecretByHeaderLine`: covers `Cookie:`, `Set-Cookie:`,
    `Authorization: Bearer`, `X-Api-Key:`.
  - `TestDetectSecretByJSONKey`: `"author":"x"` is NOT a secret;
    `"session_token":"abc123xyz"` is.
  - `TestDetectBasicAuthDecoded`.
  - `TestDetectURLAndJSONEscapedForms`: `joao.silva%40acmebank.pt` and
    `joao.silva@acmebank.pt` are found with the right `Encoding`.
  - `TestStoplistNotLiteralScanned`: enrolled username `admin`; the text
    `/admin panel` gives no span.
  - `TestMinLen3`.
  - `TestDetectJWTFormat`.
  - `TestDetectPEMBlock`.
- [ ] **Step 2:** `go test ./membrane/ -run TestDetect\|TestStoplist\|TestMinLen` → FAIL.
- [ ] **Step 3: Implement.**
  - Port the key regexes from middlehack `redactor.py`: `PASSWORD_KEY_RE`,
    `USERNAME_KEY_RE`, `SECRET_KEY_RE`, `EMAIL_KEY_RE`, and `DOMAIN_TOKEN_RE`.
  - Port the secret formats from cockpit `membrane.py` `_SECRET_RES`.
  - Encoded views map offsets back to the raw text so replacement can re-encode
    in place.
- [ ] **Step 4:** Run the same command → PASS.
- [ ] **Step 5: Commit** `feat(membrane): detector pipeline with encodings`.

### Task 5: Engine: ToModel / ToReal with derivation

**Files:**
- Create: `membrane/engine.go`, `membrane/derive.go`, `membrane/walk.go` (JSON
  and `CompletionRequest`/`Message` walkers)
- Test: `membrane/engine_test.go`

**Interfaces:**
- Consumes: Tasks 3–4.
- Produces:
  - `type Engine struct` and `NewEngine(s *Store, p *Pipeline) *Engine`
  - `type Report struct{ Counts map[Kind]int; Enrolled int; Flags []string }`
  - `(*Engine).ToModel(text string, prov Provenance) (string, Report, error)`
  - `(*Engine).ToReal(text string) (string, []string /*unresolved alias-shaped*/)`
  - `(*Engine).ToModelJSON(raw json.RawMessage, prov Provenance) (json.RawMessage, Report, error)`.
    It walks string values only and re-marshals only if something changed.
  - `(*Engine).ToRealJSON(raw json.RawMessage) (json.RawMessage, []string)`
  - `(*Engine).ToModelRequest(req llm.CompletionRequest, prov Provenance) (llm.CompletionRequest, Report, error)`.
    Covers System, text, thinking, tool_use Input and tool_result Content
    (recursive); Tools are untouched. It must deep-copy and never mutate the
    caller's slices.
  - `(*Engine).ToRealMessage(m llm.Message) (llm.Message, []string)`
  - `(*Engine).LeakCheck(serialised []byte) (hits []LeakHit)`, where
    `LeakHit{Kind Kind; Offset int}` and the value is never included. Scans raw
    plus the URL, JSON and HTML decoded views with the dictionary.
  - `(*Engine).AliasShaped(text string) []string`: matches `[0-9a-f]{6}\.example`,
    `240.0.0.0/4` IPs, `2001:db8::/32`, and `(ORG|PRODUCT|PERSON|user)-[0-9a-f]{4}`.
  - `type Suspicion struct{ Start, End int; Text string }` and
    `(*Engine).Suspicious(text string) []Suspicion`: capitalised multi-word runs
    (2–4 words, not sentence-initial-only) and domain-shaped tokens outside known
    roots that are not model-known. Used by preview and audit flags.

- [ ] **Step 1: Write failing tests:**
  - `TestRoundTripFixture`: the spec §-style goal text (Acme Bank example from
    the design conversation) passes through ToModel with no original remaining
    (assert via `LeakCheck` is empty), and ToReal gives the exact original.
  - `TestKindConfusion`: a fake API key placed in a `password` field maps back.
  - `TestDeriveSubdomain`: `dev.<alias root>` → `dev.acmebank.pt`, and the host
    gets enrolled.
  - `TestDeriveIPInBlock`.
  - `TestDeriveCIDRNarrow`: `/28` inside a block is OK; `/16` is unresolved.
  - `TestUnknownAliasUnresolved`: `ffffff.example` stays and is returned in the
    unresolved list.
  - `TestModelIntroducedDomainPassthrough`: a domain first seen in ToReal input
    is marked model-known and is not aliased later by ToModel.
  - `TestRealAliasShapedValueEnrolled` (Review Focus 4): target output containing
    a real `240.1.2.3` is enrolled and aliased, not treated as an alias.
  - `TestMultiEncodingSecret` (Review Focus 2).
  - `TestDeterministicAcrossCalls`: the same request twice gives byte-identical
    output.
  - `TestToModelRequestDoesNotMutateInput`.
- [ ] **Step 2:** `go test ./membrane/ -run 'TestRoundTrip|TestKind|TestDerive|TestUnknown|TestModelIntro|TestRealAlias|TestMultiEnc|TestDeterm|TestToModelReq'` → FAIL.
- [ ] **Step 3: Implement.** ToReal order:
  1. Exact alias lookup through an automaton over aliases.
  2. Derivation rules (§6).
  3. Collect leftover `AliasShaped` values as unresolved.

  Real values that look alias-shaped are kept distinct, because `OriginalFor`
  is only populated by aliases the store minted.
- [ ] **Step 4:** Run the same command → PASS.
- [ ] **Step 5: Commit** `feat(membrane): bidirectional engine with derivation and leak check`.

### Task 6: JWT structure preservation

**Files:**
- Create: `membrane/jwt.go`
- Test: `membrane/jwt_test.go`

**Interfaces:**
- Consumes: Task 5 `Engine`. Hook it into the engine's span replacement for spans
  of `KindToken` that parse as JWTs.
- Produces:
  - `(*Engine).jwtToModel(tok string, prov Provenance) (string, error)`
  - `(*Engine).jwtToReal(tok string) string`

- [ ] **Step 1: Write failing tests:**
  - `TestJWTClaimsAliased`: the payload `{"sub":"joao.silva@acmebank.pt","iss":"https://sso.acmebank.pt"}`
    has aliased claims after ToModel and still decodes as valid JSON; the header
    is preserved; the signature segment differs but has the same length.
  - `TestJWTExactRoundTrip`.
  - `TestJWTEditedByModel`: change the header to `alg:none` and drop the
    signature; ToReal gives real claims and `alg:none`.
- [ ] **Step 2:** `go test ./membrane/ -run TestJWT` → FAIL.
- [ ] **Step 3: Implement** with base64url, no padding, and the signature replaced
  through `FormatPreserving(KindToken, sig)`. Enrol it so the exact round trip
  works.
- [ ] **Step 4:** Run the same command → PASS.
- [ ] **Step 5: Commit** `feat(membrane): structure-preserving JWT aliasing`.

### Task 7: Provider decorator (Complete and Stream)

**Files:**
- Create: `membrane/provider.go`, `membrane/stream.go`
- Test: `membrane/provider_test.go`

**Interfaces:**
- Consumes: Task 5 `Engine`, `llmrec.TaskIDFrom`, `transcript` session id from ctx.
- Produces:
  - `type Auditor interface{ Record(ctx context.Context, ev Event) error }`
  - `type Event struct{ TaskID, Session, Role, Profile, Direction string;
    Report Report; Blocked bool; BlockReason string; RequestSHA256 string }`
  - `func Wrap(inner llm.Provider, e *Engine, a Auditor, profile string, opts ...Option) llm.Provider`
    and `type Option func(*wrapped)`. Task 9 adds `WithSyncer(s Syncer) Option`.
  - `var ErrLeakBlocked = errors.New("membrane: request blocked by leak check")`

Behaviour:
- Request: `ToModelRequest` → `json.Marshal` → `LeakCheck`. On hits, audit with
  `Blocked=true` and return `ErrLeakBlocked`. Otherwise audit with
  `RequestSHA256` of that serialisation and forward.
- Complete: `ToRealMessage` plus ToReal of the returned text string.
- Stream:
  - text and thinking deltas go through a hold-back buffer of
    `maxAliasLen = 64` chars, flushed at block boundaries and `message_stop`;
  - `tool_input_delta` is buffered per `ToolIndex` and emitted as one de-aliased
    delta right before the next `tool_use_start`, `message_delta` or
    `message_stop`;
  - all other events keep their order.
- Signed thinking blocks (`Signature != ""`): cache `sha256(signature) → aliased
  thinking text` on the way in, and on the way out replay the cached text
  verbatim instead of re-aliasing.
- Role is parsed from the session id (`exp<N>-planner|worker|main|goals|compactor`,
  `conv-<id>` → `chat`).

- [ ] **Step 1: Write failing tests** with a scripted fake `llm.Provider`:
  - `TestWrapCompleteRoundTrip`: the fake asserts the received request has no
    originals; the returned tool_use input reaches the caller with real values.
  - `TestStreamAliasSplitAcrossDeltas` (Review Focus 1): `"portal.a1b"` and
    `"2c3.example"` in two text deltas, and a tool JSON split across three deltas.
    The caller sees real values, and the event type sequence equals the inner
    sequence with merged tool deltas.
  - `TestLeakBlocked`: a stub engine that leaves an original in place gives
    `ErrLeakBlocked`, inner is not called, and the audit event has `Blocked=true`.
  - `TestEngineErrorFailsClosed`.
  - `TestSignedThinkingReplayedVerbatim`.
  - `TestAuditHasRequestHashNotOriginals`.
- [ ] **Step 2:** `go test ./membrane/ -run 'TestWrap|TestStream|TestLeak|TestEngineErr|TestSigned|TestAudit'` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Run the same command with `-race` → PASS.
- [ ] **Step 5: Commit** `feat(membrane): llm.Provider decorator with streaming de-aliasing`.

### Task 8: Wiring: fail-closed provider construction and trusted derivation

**Files:**
- Modify: `agent/provider.go` (`Config` gets `Membrane *membrane.Engine`,
  `MembraneAudit membrane.Auditor` and `ProfileName string`; `NewProvider` wraps
  the result at `:304`)
- Create: `agent/membrane_mode.go`, `server/membrane.go` (builds the
  Store/Engine/Auditor at startup, holds them on `Server`), `membrane/audit_db.go`
  (`DBAuditor` implementing `Auditor` via `AppendMembraneEvent`)
- Modify: `server/server.go`. Set `cfg.Membrane`/`MembraneAudit`/`ProfileName` in
  `loadProfileConfig` (`:495`) and in the env/global path before `:440`, and in
  validation `:1364`. Construct at server start before any provider is built.
- Test: `agent/membrane_mode_test.go`, `server/membrane_test.go`

**Interfaces:**
- Produces:
  - `func MembraneRequired(baseURL string) bool`: false only when the host is a
    loopback/RFC 1918/ULA literal IP or `localhost`, or when
    `os.Getenv("ARTEX_MEMBRANE") == "off"`.
  - `NewProvider` returns `errors.New("membrane required but not initialised")`
    when it is required and `c.Membrane == nil`.
  - `(*Server).membraneStatus() MembraneStatus{Enabled, Override bool; Entries int; KeysSource string}`.
  - When the override is active, startup appends one audit event
    `Direction:"override"`.

- [ ] **Step 1: Write failing tests:**
  - `TestMembraneRequiredHosts`: a table of `https://api.kimi.com/coding/v1` →
    true, `http://127.0.0.1:11434/v1` → false, `http://10.0.0.5:8000` → false,
    `http://localhost:1234` → false, `http://[fd00::1]:8000` → false, and
    `http://example.local` → true (hostnames other than localhost are not
    resolved).
  - `TestNewProviderFailsClosed`.
  - `TestNewProviderWrapsRemote`: use a test HTTP server as the base URL with
    `ARTEX_MEMBRANE` unset. The server is local, so set it via a test hook
    `membraneRequiredFn` to force true; assert the request body it receives
    contains aliases.
- [ ] **Step 2:** `go test ./agent/ -run Membrane\|TestNewProvider && go test ./server/ -run Membrane` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Run the same commands → PASS, then run `go build ./...`.
- [ ] **Step 5: Commit** `feat: wrap remote LLM providers with the membrane (fail-closed)`.

### Task 9: Seeding from scope, credentials and task text

**Files:**
- Create: `server/membrane_seed.go`
- Modify: `server/goals.go:28` (`launchTask` calls `s.membraneSyncTask(t)` before
  `s.seed`), `server/membrane.go` (startup `membraneSyncAll`)
- Modify: `membrane/provider.go` (before transforming, call an optional
  `Syncer.SyncTask(ctx, taskID)`, throttled to once per 30s per task, so that
  scope the agents add mid-run, such as `add_task_scope`, is enrolled without
  hooking every writer)
- Test: `server/membrane_seed_test.go`

**Interfaces:**
- Consumes: `db.DB` company/scope/asset/credential readers (`TaskCredentials`
  `db/task_credentials.go:84`, `db/task_scope.go`, `db/company_scope.go`,
  `db/companies.go`), Task 3 `Enroll`/`SeedCIDR`, Task 5 `ToModel` (to enrol
  structural detections in goal/description).
- Produces:
  - `type Syncer interface{ SyncTask(ctx context.Context, taskID string) error }`
    (in `membrane`), implemented by `*Server`.
  - `(*Server).membraneSyncTask(t *Task) error`
  - `(*Server).membraneSyncAll() error`
  - `func BrandVariants(name string) []string` (in `membrane/brand.go`):
    `"Acme Bank"` → {`Acme Bank`, `AcmeBank`, `acme-bank`, `acmebank`}; a root
    `acmebank.pt` → {`acmebank`}. Variants shorter than 4 chars are dropped.

- [ ] **Step 1: Write failing tests:**
  - `TestBrandVariants`.
  - `TestSyncTaskEnrollsEverything`, against a test DB: a company "Acme Bank"
    with scope domain `acmebank.pt` and CIDR `185.12.40.0/24`, a task scope
    keyword `AcmeOnline`, a credential `joao.silva`/`hunter2`, and a goal
    mentioning `api.acmebank.pt`. After sync, every one of them has an alias,
    and `ToModel(goal)` passes `LeakCheck`.
  - `TestSyncThrottle`.
- [ ] **Step 2:** `go test ./server/ -run MembraneSync\|TestBrand && go test ./membrane/ -run TestBrand` → FAIL.
- [ ] **Step 3: Implement.** Credentials are enrolled as `KindUsername` and
  `KindPassword`, so graph_overview carries fakes and the model logs in with
  fakes that map back.
- [ ] **Step 4:** Run the same commands → PASS.
- [ ] **Step 5: Commit** `feat: seed membrane dictionary from scope, credentials and task text`.

### Task 10: Tool guard and web_search rule

**Files:**
- Modify: `guard/guard.go` (`Guard` gets an optional
  `membraneCheck func(tool string, input []byte) (block bool, reason string)`,
  evaluated first in `preToolUse` (`:57`), recorded in the audit with
  action=block)
- Create: `membrane/toolguard.go`
- Modify: `server/intercept.go:28` and `server/manager.go:872`, which construct
  guards, to pass `engine.ToolCheck` when the membrane is active
- Test: `membrane/toolguard_test.go`, `guard/guard_membrane_test.go`

**Interfaces:**
- Produces: `(*Engine).ToolCheck(tool string, input []byte) (block bool, reason string)`.
  - It blocks when `AliasShaped` finds a value in the input that is **not** a
    known original in the store. A real `240.1.2.3` taken from target output is
    allowed, which keeps Review Focus 4 consistent; add test
    `TestToolCheckAllowsRealAliasShaped`. Reason:
    `"unknown alias <value> — use only names from your context"`. The value
    echoed back is alias-shaped, never an original.
  - For `tool == "web_search"`, it also blocks when the dictionary finds any
    original. Reason: `"search for the technology or CVE, not the target"`.

- [ ] **Step 1: Write failing tests:**
  - `TestToolCheckBlocksUnresolvedAlias`: Bash `nmap 240.9.9.0/16`.
  - `TestToolCheckAllowsReal`.
  - `TestWebSearchBlocksOriginal`.
  - `TestWebSearchAllowsTech`: `"Spring Boot actuator CVE"`.
  - `TestGuardRunsMembraneCheckFirst`.
- [ ] **Step 2:** `go test ./membrane/ -run TestToolCheck\|TestWebSearch && go test ./guard/` → FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Run the same commands → PASS.
- [ ] **Step 5: Commit** `feat: membrane tool guard and web_search rule`.

### Task 11: Verification, evidence export, preview and key destruction (API + CLI)

**Files:**
- Create: `membrane/verify.go`, `membrane/evidence.go`, `server/membrane_api.go`
- Modify: `server/server.go` (routes next to `:705`), `cmd/artex/main.go`
  (subcommand `membrane verify --task <id>`)
- Test: `membrane/verify_test.go`, `server/membrane_api_test.go`

**Interfaces:**
- Produces:
  - `func Verify(e *Engine, records []VerifyRecord) VerifyResult` where
    `VerifyRecord{ID int64; Raw string}` comes from `llm_records.raw_request`, and
    `VerifyResult{Checked, Failed int; FailedIDs []int64; ChainOK bool}`.
  - `func BuildEvidence(in EvidenceInput) (markdown string, jsonDoc []byte)`.
    Covers the §10.3 content, including the proof level (`"request-hash"` or
    `"raw-bytes"`), the §7.2 limits text and the contract-test reference
    (`go test ./membrane/... -run Contract`), and never includes the mapping.
  - Routes:
    - `GET /api/membrane/status` returns `membraneStatus`.
    - `POST /api/membrane/preview` takes `{text, companyIds[], taskId?}` and
      returns `{aliased, spans:[{start,end,kind,state:"replaced"}],
      suspicious:[{start,end,text}]}`. Preview runs on a **dry-run engine
      view**: it must not enrol, and computes aliases without persisting.
    - `GET /api/tasks/{id}/membrane/events?page&size`.
    - `POST /api/tasks/{id}/membrane/verify`.
    - `GET /api/tasks/{id}/membrane/evidence?format=md|json`.
    - `POST /api/companies/{id}/membrane/destroy` returns 409
      `{references:{…}}` when `MembraneCompanyReferences` is non-zero; otherwise
      it purges and appends an audit event.

- [ ] **Step 1: Write failing tests:**
  - `TestVerifyDetectsPlantedOriginal`.
  - `TestEvidenceHasNoOriginals`: run LeakCheck over the produced markdown.
  - `TestPreviewDoesNotEnroll`: the store count is unchanged.
  - `TestDestroyRefusedWhileReferenced`, then `TestDestroyPurges`.
  - `TestStatusEndpoint`.
- [ ] **Step 2:** `go test ./membrane/ -run TestVerify\|TestEvidence && go test ./server/ -run MembraneAPI\|TestPreview\|TestDestroy` → FAIL.
- [ ] **Step 3: Implement.** Add a dry-run mode to `Engine`: `WithDryRun()`
  returns an engine copy whose `Enroll` derives without persisting.
- [ ] **Step 4:** Run the same commands → PASS, then
  `go run ./cmd/artex membrane verify --task <id>` against a dev DB prints
  `checked=N failed=0 chain=ok`.
- [ ] **Step 5: Commit** `feat: membrane verify, evidence export, preview and key destruction`.

### Task 12: UI

**Files:**
- Modify: `web/src/lib/api.ts` (client functions for the Task 11 routes)
- Modify: `web/src/app/(main)/function/tasks/page.tsx`. Add a "Preview what the AI
  sees" panel in the create-task form beside goal/description, debounced at
  500 ms. It shows the aliased text with replaced spans in green and suspicious
  spans in amber, each with an "Add as sensitive term" button that adds a task
  scope `keyword`, which the create payload already supports via its scope
  fields.
- Create: `web/src/app/(main)/function/tasks/detail/_tabs/membrane-tab.tsx` and
  register it in `detail/page.tsx`. It shows an events table (counts, flags,
  blocked), a "Verify now" button with its result, and "Export evidence" (md/json)
  buttons.
- Modify: `web/src/app/(main)/system/llm/…` with a read-only badge per profile,
  "membrane on" or "trusted local", computed client-side with the same rule as
  `MembraneRequired` or returned by the profiles API.
- Modify: `web/src/app/(main)/layout.tsx` to show a red banner when
  `status.override`.
- Modify: the LLM records view, adding an operator/model view toggle
  (`request_body` vs `raw_request`).

- [ ] **Step 1:** Implement the API client functions and types in `api.ts`.
- [ ] **Step 2:** Build the preview panel, then the membrane tab, badge, banner
  and toggle.
- [ ] **Step 3:** `cd web && npm run lint && npm run build` → no errors.
- [ ] **Step 4:** Use the `run` skill to launch ARTEX. Create a task whose goal
  contains `https://portal.acmebank.pt` and `Acme Bank`, and check that the
  preview shows `portal.<hex>.example` and amber on `Acme Bank` until it is added
  as a term. Take a screenshot.
- [ ] **Step 5: Commit** `feat(web): membrane preview, task tab, profile badge, override banner`.

### Task 13: End-to-end contract suite

**Files:**
- Create: `membrane/contract_test.go` (all test names prefixed `TestContract`)
- Create: `membrane/testdata/contract/` (fixture scope, credentials and a scripted
  multi-turn conversation)

**Interfaces:**
- Consumes: all `membrane` APIs, plus a scripted fake `llm.Provider` that records
  every received request and replies with tool calls in alias space.

- [ ] **Step 1: Write the contract tests**, porting the middlehack `client.py`
  scenario to ARTEX shapes:
  - recon → login with the fake creds → IDOR response containing another user's
    email and password → reuse of the IDOR'd password → JWT tamper → curl `-v`
    output with `Set-Cookie` → model-introduced OAST domain → subdomain guess →
    `/28` sweep.
  - Assertions:
    1. No received request contains any fixture original, in raw, URL, JSON or
       HTML form.
    2. Every tool input the harness would execute contains only real values and
       no alias-shaped residue.
    3. `/16` sweep and unknown-alias steps are blocked by `ToolCheck`.
    4. Audit events equal the request count, and the chain verifies.
    5. Re-running the conversation gives byte-identical requests.
- [ ] **Step 2:** `go test ./membrane/ -run TestContract -race` → PASS. Any
  failure here is a bug in an earlier task; fix it there and re-run.
- [ ] **Step 3:** `go test ./...` → PASS. Packages without Postgres skip as before.
- [ ] **Step 4: Commit** `test(membrane): end-to-end contract suite`.
