package membrane

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Autumn-27/artex/db"
)

// Version identifies the membrane's alias derivation and evidence format.
const Version = "1 (derive-v1)"

// ContractTestRef is the command that runs the membrane contract suite
// (spec §10.4), referenced from every evidence export.
const ContractTestRef = "go test ./membrane/... -run Contract"

// RequestHashLabel names what an audit event's request_sha256 covers.
const RequestHashLabel = "canonical request hash (pre-serialisation form that was leak-checked)"

// Boot audit events: every server start appends one "start" event whose
// flags hold StartFlagOverride ("override:true") when ARTEX_MEMBRANE=off was
// in force for that run, else "override:false". A run lasts until the next
// start event.
const (
	DirectionStart     = "start"
	StartFlagOverride  = "override:true"
	StartFlagMembraned = "override:false"
)

// LimitsText states the known limits of the membrane (spec §2 non-goals,
// §7.2) as the evidence export reports them.
var LimitsText = []string{
	"Unknown free text is not guaranteed to be caught: a client name or identifier nobody declared and no pattern recognises can pass. The preview panel and the audit flags (suspicious_name, suspicious_domain) mitigate this.",
	"Arbitrary base64/hex blobs, signed cookies and compressed data are not decoded. Values hidden inside them are only caught when the whole blob is a known secret (it is then replaced as an opaque fake). URL encoding, JSON \\u escapes, HTML entities, Authorization: Basic credentials and JWT header/payload segments are decoded and checked.",
	"Non-LLM egress (notifications, remote MCP servers, enrichment probes) is not membraned in v1.",
	"Local transcripts and database rows that already hold real data are not encrypted by the membrane.",
	"Profiles marked trusted (local models) skip the membrane; their records carry no membrane hash, are listed as unmembraned and are not verified.",
}

// ExcerptsNote explains why the export carries no model-view excerpts
// (spec §10.3 lists them).
const ExcerptsNote = "Model-view excerpts are omitted by design: an aliased excerpt can still carry an original the membrane was never told about (undeclared free text), and this export must be safe to hand to third parties. The recorded wire bodies (llm_records.raw_request) are the model view; they stay in ARTEX."

// EvidenceInput is everything one task's evidence export is built from.
// None of it may hold the mapping; free-text event fields (block reasons,
// flags, profile names) are reduced to fixed vocabularies or redacted.
type EvidenceInput struct {
	TaskID      string
	GeneratedAt time.Time
	// Events are the task's audit events (any order).
	Events []db.MembraneEvent
	// PeriodFrom/PeriodTo bound the task (created to completed, or now).
	// Zero values fall back to the span of Events.
	PeriodFrom, PeriodTo time.Time
	// PeriodFromTask reports that the period came from the task row.
	PeriodFromTask bool
	// Boots are the "start" events whose run overlaps the period: the last
	// boot at or before PeriodFrom and every boot within the period.
	Boots []db.MembraneEvent
	// BootHistoryComplete is false when no boot event precedes the period
	// (history recorded before boot events existed): the state at task start
	// is then unknown.
	BootHistoryComplete bool
	// LegacyOverrides are "override" events within the period (written at
	// every overridden start, also before boot events existed).
	LegacyOverrides []db.MembraneEvent
	// Verify is the offline verification result (chain check included).
	Verify VerifyResult
	// ChainHead is the chain head at export time.
	ChainHead db.MembraneChainHead
	// Engine, when set, redacts any profile name holding an enrolled
	// original.
	Engine *Engine
}

// EvidenceDoc is the JSON evidence document.
type EvidenceDoc struct {
	Schema          string         `json:"schema"`
	MembraneVersion string         `json:"membrane_version"`
	GeneratedAt     time.Time      `json:"generated_at"`
	TaskID          string         `json:"task_id"`
	Period          EvidencePeriod `json:"period"`
	Profiles        []string       `json:"profiles"`
	Requests        struct {
		Total     int `json:"total"`
		Forwarded int `json:"forwarded"`
		Blocked   int `json:"blocked"`
	} `json:"requests"`
	CountsByKind map[string]int `json:"counts_by_kind"`
	Enrolled     int            `json:"enrolled"`
	Blocks       struct {
		Total     int            `json:"total"`
		Reasons   map[string]int `json:"reasons"`
		LeakKinds map[string]int `json:"leak_kinds"`
	} `json:"blocks"`
	Flags map[string]int `json:"flags"`
	Proof struct {
		Level            string       `json:"level"`
		RequestHash      string       `json:"request_hash"`
		RequestsHashed   int          `json:"requests_hashed"`
		RawRecords       int          `json:"raw_records"`
		Verify           VerifyResult `json:"verify"`
		Statement        string       `json:"statement"`
		LevelExplanation string       `json:"level_explanation"`
	} `json:"proof"`
	Chain struct {
		OK         bool                 `json:"ok"`
		FirstBadID int64                `json:"first_bad_id,omitempty"`
		Head       db.MembraneChainHead `json:"head"`
		Note       string               `json:"note"`
	} `json:"chain"`
	Override      EvidenceOverrideState `json:"override"`
	Limits        []string              `json:"limits"`
	ExcerptsNote  string                `json:"excerpts_note"`
	ContractTests string                `json:"contract_tests"`
	MappingNote   string                `json:"mapping_note"`
}

// EvidencePeriod is the task's period: from the task row (created to
// completed, or the export time) when Source is "task", else the span of
// its audit events ("events").
type EvidencePeriod struct {
	From   *time.Time `json:"from"`
	To     *time.Time `json:"to"`
	Source string     `json:"source"`
}

// EvidenceOverrideState says whether ARTEX_MEMBRANE=off was in force for any
// server run overlapping the task's period.
type EvidenceOverrideState struct {
	InForce             bool          `json:"in_force"`
	Boots               []EvidenceRun `json:"boots"`
	BootHistoryComplete bool          `json:"boot_history_complete"`
	Statement           string        `json:"statement"`
}

// EvidenceRun is one server start overlapping the period (id and time only).
type EvidenceRun struct {
	ID       int64     `json:"id"`
	TS       time.Time `json:"ts"`
	Override bool      `json:"override"`
}

const chainNote = "The audit chain links each event to the hash of its predecessor, so editing or deleting an event in the middle is detected. " +
	"Deleting the newest events leaves a consistent shorter chain, so to detect truncation compare this head with an earlier export: " +
	"the chain is intact only if the current count is at least the earlier head.count AND the event with id = earlier head.last_id still has hash = earlier head.hash."

const levelExplanation = "raw-bytes: every forwarded request is paired, by its canonical request hash, with a recorded wire body, and those bodies were re-scanned offline. " +
	"request-hash: each forwarded request's audit event holds the SHA-256 of the canonical request (the pre-serialisation form that was leak-checked before sending), " +
	"but not every forwarded request has a recorded wire body (recording off or records missing)."

var (
	leakHitRE  = regexp.MustCompile(`\b([a-z][a-z0-9_]*)@[0-9]+\b`)
	knownKinds = map[string]bool{}
	// knownVocab lists every block reason and flag the membrane writes
	// (provider.go, toolguard.go, engine.go), in snake_case.
	knownVocab = map[string]bool{
		"suspicious_name": true, "suspicious_domain": true, "unresolved": true,
		RuleUnresolvedAlias: true, RuleWebSearchOriginal: true,
		"no_engine": true, "seed_sync_failed": true, "transform_failed": true, "serialise_failed": true,
	}
)

func init() {
	for _, k := range []Kind{KindDomain, KindIPv4, KindIPv6, KindEmail, KindOrg, KindProduct, KindPerson,
		KindUsername, KindPassword, KindToken, KindPhone, KindIBAN, KindNIF, KindCard, KindPrivateKey} {
		knownKinds[string(k)] = true
	}
}

// vocab reduces a free-text reason or flag to its fixed-vocabulary key
// ("unresolved:3" is "unresolved", "seed sync failed" is
// "seed_sync_failed"); anything outside the vocabulary is "other", so a
// value can never pass.
func vocab(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ':'); i > 0 {
		s = s[:i]
	}
	s = strings.ReplaceAll(s, " ", "_")
	if !knownVocab[s] {
		return "other"
	}
	return s
}

func tp(t time.Time) *time.Time { u := t.UTC(); return &u }

// BuildEvidence renders the evidence export of one task (spec §10.3) as
// Markdown and JSON. It never includes the mapping, an original, a session
// id or a free-text reason.
func BuildEvidence(in EvidenceInput) (markdown string, jsonDoc []byte) {
	d := EvidenceDoc{
		Schema:          "artex-membrane-evidence/v2",
		MembraneVersion: Version,
		GeneratedAt:     in.GeneratedAt.UTC(),
		TaskID:          in.TaskID,
		Profiles:        []string{},
		CountsByKind:    map[string]int{},
		Flags:           map[string]int{},
		Limits:          LimitsText,
		ExcerptsNote:    ExcerptsNote,
		ContractTests:   ContractTestRef,
		MappingNote:     "The original-to-alias mapping and the membrane keys are never part of this export.",
	}
	d.Blocks.Reasons, d.Blocks.LeakKinds = map[string]int{}, map[string]int{}
	profiles := map[string]bool{}
	var hashed int
	var evFrom, evTo *time.Time
	for _, ev := range in.Events {
		ts := ev.TS.UTC()
		if evFrom == nil || ts.Before(*evFrom) {
			evFrom = tp(ts)
		}
		if evTo == nil || ts.After(*evTo) {
			evTo = tp(ts)
		}
		if ev.Profile != "" {
			profiles[ev.Profile] = true
		}
		for k, n := range ev.Counts {
			if knownKinds[k] {
				d.CountsByKind[k] += n
			}
		}
		d.Enrolled += ev.Enrolled
		for _, f := range ev.Flags {
			d.Flags[vocab(f)]++
		}
		if ev.Direction == "request" {
			d.Requests.Total++
			if ev.Blocked {
				d.Requests.Blocked++
			} else {
				d.Requests.Forwarded++
				if ev.RequestSHA256 != "" {
					hashed++
				}
			}
		}
		if ev.Blocked {
			d.Blocks.Total++
			reason := ev.BlockReason
			if strings.HasPrefix(reason, "leak check:") {
				d.Blocks.Reasons["leak_check"]++
				for _, m := range leakHitRE.FindAllStringSubmatch(reason, -1) {
					if knownKinds[m[1]] {
						d.Blocks.LeakKinds[m[1]]++
					}
				}
			} else {
				d.Blocks.Reasons[vocab(reason)]++
			}
		}
	}
	if !in.PeriodFrom.IsZero() {
		d.Period = EvidencePeriod{From: tp(in.PeriodFrom), To: tp(in.PeriodTo), Source: "events"}
		if in.PeriodFromTask {
			d.Period.Source = "task"
		}
	} else {
		d.Period = EvidencePeriod{From: evFrom, To: evTo, Source: "events"}
	}
	for p := range profiles {
		d.Profiles = append(d.Profiles, p)
	}
	sort.Strings(d.Profiles)
	for i, p := range d.Profiles {
		if !safeProfile(in.Engine, p) {
			d.Profiles[i] = fmt.Sprintf("profile-%d (name redacted)", i+1)
		}
	}

	d.Override = overrideState(in)

	v := in.Verify
	if v.FailedIDs == nil {
		v.FailedIDs = []int64{}
	}
	if v.FailedKinds == nil {
		v.FailedKinds = map[string]int{}
	}
	if v.Note == "" {
		v.Note = VerifyNote
	}
	d.Proof.RequestHash = RequestHashLabel
	d.Proof.RequestsHashed = hashed
	d.Proof.RawRecords = v.Checked
	d.Proof.Verify = v
	d.Proof.Level = "request-hash"
	if d.Requests.Forwarded > 0 && v.Forwarded == d.Requests.Forwarded && v.Unpaired == 0 && v.Paired >= v.Forwarded {
		d.Proof.Level = "raw-bytes"
	}
	switch v.Result {
	case VerifyPass:
		if v.Forwarded == 0 {
			d.Proof.Statement = "No request was forwarded to a remote model through the membrane for this task, so there was nothing to re-scan; the audit chain is intact. This shows no membrane traffic, not that membraned traffic was verified."
		} else {
			d.Proof.Statement = "Offline verification passed: every forwarded request's recorded wire body was re-scanned and no enrolled original was found, and the audit chain is intact."
		}
	case VerifyFail:
		d.Proof.Statement = "Offline verification FAILED: see the failed record ids and kinds, and the chain status."
	case VerifyInconclusive:
		d.Proof.Statement = "Offline verification is INCONCLUSIVE: " + v.Reason + ". No failure was found in what could be checked."
	default:
		d.Proof.Statement = "Offline verification was not run."
	}
	if d.Override.InForce {
		d.Proof.Statement += " The membrane was overridden for part or all of the period: requests made then were not membraned and left no audit events, so this proof does not cover them."
	}
	d.Proof.LevelExplanation = levelExplanation
	d.Chain.OK, d.Chain.FirstBadID = v.ChainOK, v.ChainFirstBadID
	d.Chain.Head, d.Chain.Note = in.ChainHead, chainNote

	js, _ := json.MarshalIndent(d, "", "  ")
	return renderEvidenceMD(&d), js
}

func overrideState(in EvidenceInput) EvidenceOverrideState {
	o := EvidenceOverrideState{Boots: []EvidenceRun{}, BootHistoryComplete: in.BootHistoryComplete}
	for _, b := range in.Boots {
		over := slices.Contains(b.Flags, StartFlagOverride)
		o.Boots = append(o.Boots, EvidenceRun{ID: b.ID, TS: b.TS.UTC(), Override: over})
		o.InForce = o.InForce || over
	}
	for _, l := range in.LegacyOverrides {
		// The same overridden boot writes a "start" and an "override" event
		// moments apart: list it once.
		twin := func(r EvidenceRun) bool {
			d := r.TS.Sub(l.TS)
			return r.Override && d < 5*time.Second && d > -5*time.Second
		}
		if !slices.ContainsFunc(o.Boots, twin) {
			o.Boots = append(o.Boots, EvidenceRun{ID: l.ID, TS: l.TS.UTC(), Override: true})
		}
		o.InForce = true
	}
	sort.Slice(o.Boots, func(i, j int) bool { return o.Boots[i].ID < o.Boots[j].ID })
	switch {
	case o.InForce:
		o.Statement = "The membrane was OVERRIDDEN (ARTEX_MEMBRANE=off) for at least one server run overlapping the task's period: remote models then received real data."
	case !o.BootHistoryComplete:
		o.Statement = "No override was recorded during the period, but no server start is recorded before the period began, so the membrane state at task start cannot be shown from the audit log."
	default:
		o.Statement = "The membrane was not overridden: every server run overlapping the task's period started with the membrane on."
	}
	return o
}

// safeProfile reports whether a profile name can be shown: a plain name
// that holds no enrolled original.
func safeProfile(e *Engine, p string) bool {
	if len(p) > 80 || strings.ContainsAny(p, "\n\r") {
		return false
	}
	return e == nil || len(e.LeakCheck([]byte(p))) == 0
}

func renderEvidenceMD(d *EvidenceDoc) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	period := func(t *time.Time) string {
		if t == nil {
			return "-"
		}
		return t.Format(time.RFC3339)
	}
	w("# Identity membrane evidence: task %s\n\n", mdText(d.TaskID))
	w("- Generated: %s\n- Membrane version: %s\n- Period: %s to %s (from the %s)\n", d.GeneratedAt.Format(time.RFC3339),
		d.MembraneVersion, period(d.Period.From), period(d.Period.To), map[string]string{"task": "task record", "events": "audit events"}[d.Period.Source])
	if len(d.Profiles) == 0 {
		w("- Profiles: none recorded\n")
	} else {
		w("- Profiles: %s\n", mdText(strings.Join(d.Profiles, ", ")))
	}

	w("\n## Membrane state (override)\n\n%s\n", d.Override.Statement)
	if len(d.Override.Boots) > 0 {
		w("\nServer starts overlapping the period:\n\n")
		for _, r := range d.Override.Boots {
			state := "membrane on"
			if r.Override {
				state = "OVERRIDE (ARTEX_MEMBRANE=off)"
			}
			w("- event %d at %s: %s\n", r.ID, r.TS.Format(time.RFC3339), state)
		}
	}

	w("\n## Requests\n\n| Total | Forwarded | Blocked |\n|---|---|---|\n| %d | %d | %d |\n",
		d.Requests.Total, d.Requests.Forwarded, d.Requests.Blocked)
	w("\nValues enrolled during the task: %d\n", d.Enrolled)
	w("\n## Values replaced, by kind\n\n")
	table(&b, "Kind", d.CountsByKind)
	w("\n## Blocks\n\nBlocked events (requests and tool calls): %d\n\n", d.Blocks.Total)
	table(&b, "Reason", d.Blocks.Reasons)
	if len(d.Blocks.LeakKinds) > 0 {
		w("\nKinds found by the pre-send leak check in blocked requests:\n\n")
		table(&b, "Kind", d.Blocks.LeakKinds)
	}
	w("\n## Flags\n\n")
	table(&b, "Flag", d.Flags)

	v := d.Proof.Verify
	w("\n## Proof\n\n- Proof level: **%s**\n- Offline verification result: **%s**\n- `request_sha256` in each audit event is the %s, not the adapter's wire bytes.\n",
		d.Proof.Level, strings.ToUpper(orDash(v.Result)), d.Proof.RequestHash)
	w("- Forwarded requests: %d (with a request hash: %d); paired with a recorded wire body: %d; unpaired: %d\n",
		v.Forwarded, d.Proof.RequestsHashed, v.Paired, v.Unpaired)
	w("- Recorded wire bodies re-scanned: checked=%d failed=%d (membraned records without a body: %d, unmembraned records: %d, refused by the membrane and never forwarded: %d)\n",
		v.Checked, v.Failed, v.NoRaw, v.Unmembraned, v.Blocked)
	if v.Failed > 0 {
		ids := make([]string, len(v.FailedIDs))
		for i, id := range v.FailedIDs {
			ids[i] = fmt.Sprint(id)
		}
		w("- Failed llm_records ids: %s\n\n", strings.Join(ids, ", "))
		table(&b, "Kind found", v.FailedKinds)
	}
	w("\n%s\n\n%s\n\n%s\n", d.Proof.Statement, v.Note, d.Proof.LevelExplanation)

	chain := "ok"
	if !d.Chain.OK {
		chain = fmt.Sprintf("BROKEN (first inconsistent event id %d)", d.Chain.FirstBadID)
	}
	w("\n## Audit chain\n\n- Chain: %s\n- Head at export: last event id %d, hash `%s`, %d events\n\n%s\n",
		chain, d.Chain.Head.LastID, d.Chain.Head.Hash, d.Chain.Head.Count, d.Chain.Note)

	w("\n## Known limits\n\n")
	for _, l := range d.Limits {
		w("- %s\n", l)
	}
	w("\n## Model-view excerpts\n\n%s\n", d.ExcerptsNote)
	w("\n## Contract tests\n\nThe membrane's contract suite runs with `%s`.\n", d.ContractTests)
	w("\n%s\n", d.MappingNote)
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "not run"
	}
	return s
}

func table(b *strings.Builder, head string, m map[string]int) {
	if len(m) == 0 {
		b.WriteString("None.\n")
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(b, "| %s | Count |\n|---|---|\n", head)
	for _, k := range keys {
		fmt.Fprintf(b, "| %s | %d |\n", k, m[k])
	}
}

// mdText escapes Markdown control characters in a short text.
func mdText(s string) string {
	r := strings.NewReplacer("|", "\\|", "*", "\\*", "_", "\\_", "`", "\\`", "\n", " ", "\r", " ")
	return r.Replace(s)
}

// EvidenceSource is the part of *db.DB TaskEvidence reads.
type EvidenceSource interface {
	VerifySource
	MembraneEventsByDirection(direction string, from, to time.Time) ([]db.MembraneEvent, error)
	MembraneLastEventAtOrBefore(direction string, t time.Time) (*db.MembraneEvent, error)
	MembraneTaskPeriod(taskID string) (created time.Time, completed *time.Time, found bool, err error)
	MembraneChainHeadNow() (db.MembraneChainHead, error)
}

// TaskEvidence gathers the evidence input of taskID: its events, its period
// (task row, widened to cover its events), the server starts overlapping
// it, a fresh offline verification (chain check included) and the chain
// head at export time. The head is read first so it never names an event
// the check did not see.
func TaskEvidence(e *Engine, src EvidenceSource, taskID string, now time.Time) (EvidenceInput, error) {
	head, err := src.MembraneChainHeadNow()
	if err != nil {
		return EvidenceInput{}, fmt.Errorf("membrane evidence: chain head: %w", err)
	}
	evs, err := src.MembraneTaskEvents(taskID)
	if err != nil {
		return EvidenceInput{}, fmt.Errorf("membrane evidence: load events: %w", err)
	}
	in := EvidenceInput{TaskID: taskID, GeneratedAt: now, Events: evs, ChainHead: head, Engine: e}
	created, completed, found, err := src.MembraneTaskPeriod(taskID)
	if err != nil {
		return EvidenceInput{}, fmt.Errorf("membrane evidence: task period: %w", err)
	}
	from, to := time.Time{}, now
	if found {
		from, in.PeriodFromTask = created, true
		if completed != nil {
			to = *completed
		}
	}
	for _, ev := range evs { // a hard-deleted task, or events past completion
		if from.IsZero() || ev.TS.Before(from) {
			from = ev.TS
		}
		if ev.TS.After(to) {
			to = ev.TS
		}
	}
	if from.IsZero() {
		from = now // no task row and no events: nothing to cover
	}
	in.PeriodFrom, in.PeriodTo = from, to
	last, err := src.MembraneLastEventAtOrBefore(DirectionStart, from)
	if err != nil {
		return EvidenceInput{}, fmt.Errorf("membrane evidence: boot events: %w", err)
	}
	if last != nil {
		in.Boots = append(in.Boots, *last)
		in.BootHistoryComplete = true
	}
	during, err := src.MembraneEventsByDirection(DirectionStart, from, to)
	if err != nil {
		return EvidenceInput{}, fmt.Errorf("membrane evidence: boot events: %w", err)
	}
	for _, b := range during {
		if last == nil || b.ID != last.ID {
			in.Boots = append(in.Boots, b)
		}
	}
	// "override" events always count, whatever the boot history (a lost
	// "start" event must not hide an override): every one inside the
	// period, and the last one before it, unless a membraned boot was
	// recorded after it and before the period (that boot ended its run;
	// without this every later task would read as overridden forever).
	if in.LegacyOverrides, err = src.MembraneEventsByDirection("override", from, to); err != nil {
		return EvidenceInput{}, fmt.Errorf("membrane evidence: override events: %w", err)
	}
	lo, err := src.MembraneLastEventAtOrBefore("override", from)
	if err != nil {
		return EvidenceInput{}, fmt.Errorf("membrane evidence: override events: %w", err)
	}
	if lo != nil && !(last != nil && last.ID > lo.ID && !slices.Contains(last.Flags, StartFlagOverride)) {
		in.LegacyOverrides = append([]db.MembraneEvent{*lo}, in.LegacyOverrides...)
	}
	if in.Verify, err = verifyTask(e, src, taskID, evs); err != nil {
		return EvidenceInput{}, err
	}
	return in, nil
}
