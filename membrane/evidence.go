package membrane

import (
	"encoding/json"
	"fmt"
	"regexp"
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

// LimitsText states the known limits of the membrane (spec §2 non-goals,
// §7.2) as the evidence export reports them.
var LimitsText = []string{
	"Unknown free text is not guaranteed to be caught: a client name or identifier nobody declared and no pattern recognises can pass. The preview panel and the audit flags (suspicious_name, suspicious_domain) mitigate this.",
	"Arbitrary base64/hex blobs, signed cookies and compressed data are not decoded. Values hidden inside them are only caught when the whole blob is a known secret (it is then replaced as an opaque fake). URL encoding, JSON \\u escapes, HTML entities, Authorization: Basic credentials and JWT header/payload segments are decoded and checked.",
	"Non-LLM egress (notifications, remote MCP servers, enrichment probes) is not membraned in v1.",
	"Local transcripts and database rows that already hold real data are not encrypted by the membrane.",
	"Profiles marked trusted (local models) skip the membrane; their requests are listed as unmembraned and are not verified.",
}

// EvidenceInput is everything one task's evidence export is built from.
// None of it may hold the mapping; free-text event fields (block reasons,
// flags, profile names) are reduced to fixed vocabularies or redacted.
type EvidenceInput struct {
	TaskID      string
	GeneratedAt time.Time
	// Events are the task's audit events (any order).
	Events []db.MembraneEvent
	// Overrides are the ARTEX_MEMBRANE=off events within the task's period.
	Overrides []db.MembraneEvent
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
		LevelExplanation string       `json:"level_explanation"`
	} `json:"proof"`
	Chain struct {
		OK         bool                 `json:"ok"`
		FirstBadID int64                `json:"first_bad_id,omitempty"`
		Head       db.MembraneChainHead `json:"head"`
		Note       string               `json:"note"`
	} `json:"chain"`
	Overrides     []EvidenceOverride `json:"overrides"`
	Limits        []string           `json:"limits"`
	ContractTests string             `json:"contract_tests"`
	MappingNote   string             `json:"mapping_note"`
}

// EvidencePeriod spans the task's first and last audit event.
type EvidencePeriod struct {
	From *time.Time `json:"from"`
	To   *time.Time `json:"to"`
}

// EvidenceOverride is one membrane override event (id and time only).
type EvidenceOverride struct {
	ID int64     `json:"id"`
	TS time.Time `json:"ts"`
}

const chainNote = "The audit chain links each event to the hash of its predecessor, so editing or deleting an event in the middle is detected. Deleting the newest events leaves a consistent shorter chain: compare head.last_id, head.hash and head.count with an earlier export to detect truncation."

const levelExplanation = "raw-bytes: every forwarded request has a recorded wire body, and those bodies were re-scanned offline for every enrolled original. request-hash: each forwarded request's audit event holds the SHA-256 of the canonical request (the pre-serialisation form that was leak-checked before sending); the wire bytes were not (all) recorded."

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

// BuildEvidence renders the evidence export of one task (spec §10.3) as
// Markdown and JSON. It never includes the mapping, an original, a session
// id or a free-text reason.
func BuildEvidence(in EvidenceInput) (markdown string, jsonDoc []byte) {
	d := EvidenceDoc{
		Schema:          "artex-membrane-evidence/v1",
		MembraneVersion: Version,
		GeneratedAt:     in.GeneratedAt.UTC(),
		TaskID:          in.TaskID,
		Profiles:        []string{},
		CountsByKind:    map[string]int{},
		Flags:           map[string]int{},
		Overrides:       []EvidenceOverride{},
		Limits:          LimitsText,
		ContractTests:   ContractTestRef,
		MappingNote:     "The original-to-alias mapping and the membrane keys are never part of this export.",
	}
	d.Blocks.Reasons, d.Blocks.LeakKinds = map[string]int{}, map[string]int{}
	profiles := map[string]bool{}
	var hashed int
	for _, ev := range in.Events {
		ts := ev.TS.UTC()
		if d.Period.From == nil || ts.Before(*d.Period.From) {
			d.Period.From = &ts
		}
		if d.Period.To == nil || ts.After(*d.Period.To) {
			t := ts
			d.Period.To = &t
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
	for p := range profiles {
		d.Profiles = append(d.Profiles, p)
	}
	sort.Strings(d.Profiles)
	for i, p := range d.Profiles {
		if !safeProfile(in.Engine, p) {
			d.Profiles[i] = fmt.Sprintf("profile-%d (name redacted)", i+1)
		}
	}
	for _, o := range in.Overrides {
		d.Overrides = append(d.Overrides, EvidenceOverride{ID: o.ID, TS: o.TS.UTC()})
	}

	d.Proof.RequestHash = RequestHashLabel
	d.Proof.RequestsHashed = hashed
	d.Proof.RawRecords = in.Verify.Checked
	d.Proof.Verify = in.Verify
	if d.Proof.Verify.FailedIDs == nil {
		d.Proof.Verify.FailedIDs = []int64{}
	}
	if d.Proof.Verify.FailedKinds == nil {
		d.Proof.Verify.FailedKinds = map[string]int{}
	}
	d.Proof.Level = "request-hash"
	if d.Requests.Forwarded > 0 && in.Verify.Checked >= d.Requests.Forwarded {
		d.Proof.Level = "raw-bytes"
	}
	d.Proof.LevelExplanation = levelExplanation
	d.Chain.OK, d.Chain.FirstBadID = in.Verify.ChainOK, in.Verify.ChainFirstBadID
	d.Chain.Head, d.Chain.Note = in.ChainHead, chainNote

	js, _ := json.MarshalIndent(d, "", "  ")
	return renderEvidenceMD(&d), js
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
	w("- Generated: %s\n- Membrane version: %s\n- Period: %s to %s\n", d.GeneratedAt.Format(time.RFC3339),
		d.MembraneVersion, period(d.Period.From), period(d.Period.To))
	if len(d.Profiles) == 0 {
		w("- Profiles: none recorded\n")
	} else {
		w("- Profiles: %s\n", mdText(strings.Join(d.Profiles, ", ")))
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

	w("\n## Proof\n\n- Proof level: **%s**\n- `request_sha256` in each audit event is the %s, not the adapter's wire bytes.\n",
		d.Proof.Level, d.Proof.RequestHash)
	w("- Forwarded requests with a request hash: %d\n- Recorded wire bodies re-scanned (raw records): %d\n", d.Proof.RequestsHashed, d.Proof.RawRecords)
	v := d.Proof.Verify
	w("- Offline verification: checked=%d failed=%d (no raw body: %d, unmembraned profile: %d)\n", v.Checked, v.Failed, v.NoRaw, v.Unmembraned)
	if v.Failed > 0 {
		ids := make([]string, len(v.FailedIDs))
		for i, id := range v.FailedIDs {
			ids[i] = fmt.Sprint(id)
		}
		w("- Failed llm_records ids: %s\n\n", strings.Join(ids, ", "))
		table(&b, "Kind found", v.FailedKinds)
	}
	w("\n%s\n", d.Proof.LevelExplanation)

	chain := "ok"
	if !d.Chain.OK {
		chain = fmt.Sprintf("BROKEN (first inconsistent event id %d)", d.Chain.FirstBadID)
	}
	w("\n## Audit chain\n\n- Chain: %s\n- Head at export: last event id %d, hash `%s`, %d events\n\n%s\n",
		chain, d.Chain.Head.LastID, d.Chain.Head.Hash, d.Chain.Head.Count, d.Chain.Note)

	w("\n## Membrane override events in the period\n\n")
	if len(d.Overrides) == 0 {
		w("None: the membrane was not overridden (ARTEX_MEMBRANE=off) during the period.\n")
	} else {
		w("The membrane was overridden (ARTEX_MEMBRANE=off) at server start; remote models then received real data:\n\n")
		for _, o := range d.Overrides {
			w("- override event %d at %s\n", o.ID, o.TS.Format(time.RFC3339))
		}
	}
	w("\n## Known limits\n\n")
	for _, l := range d.Limits {
		w("- %s\n", l)
	}
	w("\n## Contract tests\n\nThe membrane's contract suite runs with `%s`.\n", d.ContractTests)
	w("\n%s\n", d.MappingNote)
	return b.String()
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
	MembraneChainHeadNow() (db.MembraneChainHead, error)
}

// TaskEvidence gathers the evidence input of taskID: its events, the
// override events within its period, a fresh offline verification (chain
// check included) and the chain head at export time. The head is read
// before the verification so it never names an event the check did not see.
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
	// A task with no events may have run entirely under the override (which
	// records no request events): then every override event up to now is
	// listed.
	from, to := time.Unix(0, 0), now
	if len(evs) > 0 {
		from, to = evs[0].TS, evs[0].TS
		for _, ev := range evs {
			if ev.TS.Before(from) {
				from = ev.TS
			}
			if ev.TS.After(to) {
				to = ev.TS
			}
		}
	}
	if in.Overrides, err = src.MembraneEventsByDirection("override", from, to); err != nil {
		return EvidenceInput{}, fmt.Errorf("membrane evidence: override events: %w", err)
	}
	if in.Verify, err = verifyTask(e, src, taskID, evs); err != nil {
		return EvidenceInput{}, err
	}
	return in, nil
}
