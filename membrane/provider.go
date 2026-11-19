package membrane

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/llmrec"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

// Auditor records membrane audit events. A Record error blocks the request
// it describes (ruling R13): a forwarded request is always recorded.
type Auditor interface {
	Record(ctx context.Context, ev Event) error
}

// Event is one audit record. It never contains originals: Report holds
// counts and flags only, BlockReason kinds and byte offsets only.
//
// Direction "request" is written exactly once per request attempt, before
// the request is forwarded (or when it is blocked). Direction "response" is
// written only when a reply carried alias-shaped values that did not
// resolve; its Report.Flags holds "unresolved:<n>".
type Event struct {
	TaskID, Session, Role, Profile, Direction string
	Report                                    Report
	Blocked                                   bool
	BlockReason                               string
	// RequestSHA256 is the hex SHA-256 of the json.Marshal of the transformed
	// llm.CompletionRequest, the exact bytes the leak check scanned.
	RequestSHA256 string
}

// ErrLeakBlocked is returned when the pre-send leak check finds an original
// in the transformed request (spec §9.1).
var ErrLeakBlocked = errors.New("membrane: request blocked by leak check")

// Option configures Wrap.
type Option func(*wrapped)

// Syncer seeds the dictionary from a task's scope, credentials and text
// (spec §7.1) and returns the task's company ids. The decorator calls it
// before transforming a request that carries a numeric task id, at most once
// per syncInterval per task after a success; a failure blocks the request
// (fail closed: seeded originals would be missing). The company ids go into
// the provenance of values auto-enrolled from that task's requests, so a
// company purge can remove them (ruling R16). Errors must not contain
// originals.
type Syncer interface {
	SyncTask(ctx context.Context, taskID string) (companyIDs []int64, err error)
}

// GlobalSyncer is optionally implemented by a Syncer: it seeds the values
// that belong to no task (companies, spec §7.1) before a request without a
// numeric task id (chat conversations, custom agents), at most once per
// syncInterval after a success; a failure blocks the request. Errors must
// not contain originals.
type GlobalSyncer interface {
	SyncGlobal(ctx context.Context) error
}

// SyncEpocher is optionally implemented by a Syncer: the epoch changes
// whenever a seed source changes (a company, its scope, a task's scope or
// credentials), which expires every throttled sync at once.
type SyncEpocher interface {
	SyncEpoch() uint64
}

// WithSyncer makes the decorator sync each task's seeds before its requests.
func WithSyncer(s Syncer) Option {
	return func(w *wrapped) { w.syncer = s }
}

// syncInterval is the minimum time between two successful syncs of a task.
const syncInterval = 30 * time.Second

// maxSyncCache bounds the per-task sync cache; expired entries are pruned
// when it is exceeded.
const maxSyncCache = 1024

type syncState struct {
	at        time.Time
	epoch     uint64
	companies []int64
}

// globalSyncKey is the sync cache key of task-less requests.
const globalSyncKey = ""

// engineAPI is the part of *Engine the decorator uses; tests substitute a
// faulty engine to prove the leak check blocks.
type engineAPI interface {
	ToModelRequest(req llm.CompletionRequest, prov Provenance) (llm.CompletionRequest, Report, error)
	LeakCheck(serialised []byte) []LeakHit
	ScrubRequest(req llm.CompletionRequest) (llm.CompletionRequest, int)
	ToReal(text string) (string, []string)
	ToRealJSON(raw json.RawMessage) (json.RawMessage, []string)
	ToRealMessage(m llm.Message) (llm.Message, []string)
	streamAliasSpans(text string) [][2]int
}

type wrapped struct {
	inner   llm.Provider
	e       engineAPI
	a       Auditor
	profile string
	sigs    *sigCache

	syncer Syncer
	now    func() time.Time
	syncMu sync.Mutex
	synced map[string]syncState
}

// Wrap returns inner behind the identity membrane: every request is
// rewritten into the alias universe, leak-checked, audited and only then
// forwarded; replies (complete and streamed) are de-aliased. A nil engine or
// auditor makes every call fail (fail closed). profile is recorded in audit
// events.
func Wrap(inner llm.Provider, e *Engine, a Auditor, profile string, opts ...Option) llm.Provider {
	var api engineAPI
	if e != nil {
		api = e
	}
	return wrap(inner, api, a, profile, opts...)
}

func wrap(inner llm.Provider, e engineAPI, a Auditor, profile string, opts ...Option) *wrapped {
	w := &wrapped{inner: inner, e: e, a: a, profile: profile, sigs: newSigCache(sigCacheEntries, sigCacheBytes),
		now: time.Now, synced: map[string]syncState{}}
	for _, o := range opts {
		o(w)
	}
	return w
}

// meta is the per-call audit context.
type meta struct {
	taskID, session, role string
}

func metaFrom(ctx context.Context) meta {
	s := transcript.SessionIDFrom(ctx)
	return meta{taskID: llmrec.TaskIDFrom(ctx), session: s, role: roleFromSession(s)}
}

func (w *wrapped) event(m meta, dir string) Event {
	return Event{TaskID: m.taskID, Session: m.session, Role: m.role, Profile: w.profile, Direction: dir, Report: newReport()}
}

// agentRoles are the lanes ARTEX encodes as exp<N>-<role>[-suffix].
var agentRoles = map[string]bool{"planner": true, "worker": true, "main": true, "goals": true, "compactor": true}

// roleFromSession maps an ARTEX transcript session id to an agent role:
// exp<N>-planner, exp<N>-worker-i<M>, exp<N>-main[-s<K>], exp<N>-goals and
// exp<N>-compactor give that role, conv-<id> gives "chat", anything else
// (side questions, connection tests, no session) "other".
func roleFromSession(id string) string {
	if rest, ok := strings.CutPrefix(id, "conv-"); ok && rest != "" {
		return "chat"
	}
	rest, ok := strings.CutPrefix(id, "exp")
	if !ok {
		return "other"
	}
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i == 0 || i >= len(rest) || rest[i] != '-' {
		return "other"
	}
	seg := rest[i+1:]
	if k := strings.IndexByte(seg, '-'); k >= 0 {
		seg = seg[:k]
	}
	if agentRoles[seg] {
		return seg
	}
	return "other"
}

// syncTask runs the syncer for a numeric task id (throttled per task after
// a success, until the syncer's epoch changes) and returns the task's
// company ids. A request without a task id (chat conversations, custom
// agents, connection tests) runs the GlobalSyncer instead, when the syncer
// has one, throttled the same way.
func (w *wrapped) syncTask(ctx context.Context, taskID string) ([]int64, error) {
	if w.syncer == nil {
		return nil, nil
	}
	gs, _ := w.syncer.(GlobalSyncer)
	if id, err := strconv.ParseInt(taskID, 10, 64); err != nil || id <= 0 {
		if gs == nil {
			return nil, nil
		}
		taskID = globalSyncKey
	}
	var epoch uint64
	if ep, ok := w.syncer.(SyncEpocher); ok {
		epoch = ep.SyncEpoch()
	}
	now := w.now()
	w.syncMu.Lock()
	st, ok := w.synced[taskID]
	w.syncMu.Unlock()
	if ok && now.Sub(st.at) < syncInterval && st.epoch == epoch {
		return slices.Clone(st.companies), nil
	}
	var companies []int64
	var err error
	if taskID == globalSyncKey {
		err = gs.SyncGlobal(ctx)
	} else {
		companies, err = w.syncer.SyncTask(ctx, taskID)
	}
	if err != nil {
		return nil, err
	}
	companies = slices.Clone(companies)
	w.syncMu.Lock()
	if len(w.synced) >= maxSyncCache {
		for k, v := range w.synced {
			if now.Sub(v.at) >= syncInterval {
				delete(w.synced, k)
			}
		}
	}
	w.synced[taskID] = syncState{at: now, epoch: epoch, companies: companies}
	w.syncMu.Unlock()
	return companies, nil
}

// provenanceFrom: the task id from llmrec (numeric ids only), source "auto".
// Company ids come from the syncer (see syncTask).
func provenanceFrom(ctx context.Context) Provenance {
	p := Provenance{Source: "auto"}
	if id, err := strconv.ParseInt(llmrec.TaskIDFrom(ctx), 10, 64); err == nil {
		p.TaskIDs = []int64{id}
	}
	return p
}

// prepare transforms, leak-checks and audits req. On any failure the
// request must not be forwarded; exactly one "request" event is recorded per
// call (unless the auditor itself is missing or failing).
func (w *wrapped) prepare(ctx context.Context, req llm.CompletionRequest) (llm.CompletionRequest, meta, error) {
	m := metaFrom(ctx)
	if w.a == nil {
		return llm.CompletionRequest{}, m, errors.New("membrane: no auditor configured, request not sent")
	}
	ev := w.event(m, "request")
	block := func(reason string, cause error) error {
		ev.Blocked, ev.BlockReason = true, reason
		if aerr := w.a.Record(ctx, ev); aerr != nil {
			return errors.Join(cause, fmt.Errorf("membrane: audit failed: %w", aerr))
		}
		return cause
	}
	if w.e == nil {
		return llm.CompletionRequest{}, m, block("no engine", errors.New("membrane: no engine configured, request not sent"))
	}
	companies, err := w.syncTask(ctx, m.taskID)
	if err != nil {
		return llm.CompletionRequest{}, m, block("seed sync failed",
			fmt.Errorf("membrane: request not sent: task seed sync failed: %w", err))
	}
	prov := provenanceFrom(ctx)
	prov.CompanyIDs = companies
	in, replay := w.stripSignedThinking(req)
	out, rep, err := w.e.ToModelRequest(in, prov)
	if err != nil {
		return llm.CompletionRequest{}, m, block("transform failed", fmt.Errorf("membrane: request not sent: %w", err))
	}
	for _, r := range replay {
		out.Messages[r.msg].Content[r.block].Thinking = r.text
	}
	body, err := json.Marshal(out)
	if err != nil {
		return llm.CompletionRequest{}, m, block("serialise failed", errors.New("membrane: request not sent: cannot serialise request"))
	}
	hits := w.e.LeakCheck(body)
	if len(hits) > 0 && len(replay) > 0 {
		// A value the model guessed in signed thinking may have been
		// enrolled since (a tool result proved it real): the replayed
		// alias-space text now carries an original. Drop those blocks
		// rather than block every later request of the conversation.
		var dropped bool
		if out, dropped, err = w.dropLeakingThinking(out, replay, prov); err != nil {
			return llm.CompletionRequest{}, m, block("transform failed", fmt.Errorf("membrane: request not sent: %w", err))
		}
		if dropped {
			rep.Flags = unionSorted(rep.Flags, []string{"signed_thinking_dropped"})
			if body, err = json.Marshal(out); err != nil {
				return llm.CompletionRequest{}, m, block("serialise failed", errors.New("membrane: request not sent: cannot serialise request"))
			}
			hits = w.e.LeakCheck(body)
		}
	}
	if len(hits) > 0 {
		// The transform kept an enrolled original the leak check finds:
		// replace it with its alias rather than block every retry of the
		// same history. Whatever is still found blocks.
		if scrubbed, n := w.e.ScrubRequest(out); n > 0 {
			sb, err := json.Marshal(scrubbed)
			if err != nil {
				return llm.CompletionRequest{}, m, block("serialise failed", errors.New("membrane: request not sent: cannot serialise request"))
			}
			out, body, hits = scrubbed, sb, w.e.LeakCheck(sb)
			rep.Flags = unionSorted(rep.Flags, []string{"leak_scrubbed"})
		}
	}
	ev.Report = rep
	if len(hits) > 0 {
		return llm.CompletionRequest{}, m, block(leakReason(hits), ErrLeakBlocked)
	}
	sum := sha256.Sum256(body)
	ev.RequestSHA256 = hex.EncodeToString(sum[:])
	if err := w.a.Record(ctx, ev); err != nil {
		return llm.CompletionRequest{}, m, fmt.Errorf("membrane: audit failed, request not sent: %w", err)
	}
	// When recording is on, the recorder's capture pairs the recorded wire
	// bytes with this event, so `membrane verify` can prove every forwarded
	// request (raw-bytes proof level).
	llmrec.CaptureFrom(ctx).SetMembraneHash(ev.RequestSHA256)
	return out, m, nil
}

// maxReasonHits bounds the hits listed in a BlockReason.
const maxReasonHits = 20

// leakReason lists kinds and byte offsets only, never values.
func leakReason(hits []LeakHit) string {
	var b strings.Builder
	b.WriteString("leak check: ")
	for i, h := range hits {
		if i == maxReasonHits {
			fmt.Fprintf(&b, ", +%d more", len(hits)-i)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s@%d", h.Kind, h.Offset)
	}
	return b.String()
}

type replayed struct {
	msg, block int
	text       string
}

// stripSignedThinking finds thinking blocks whose signature is cached and
// blanks their text in a copy of req (so the engine does not re-alias it);
// prepare puts the cached alias-space text back verbatim afterwards. An
// unknown signature (e.g. after a restart) is left for normal
// transformation; the provider may then reject the signature.
func (w *wrapped) stripSignedThinking(req llm.CompletionRequest) (llm.CompletionRequest, []replayed) {
	var rs []replayed
	copied := false
	for i, m := range req.Messages {
		msgCopied := false
		for j, b := range m.Content {
			if b.Signature == "" || b.Thinking == "" {
				continue
			}
			text, ok := w.sigs.get(b.Signature)
			if !ok {
				continue
			}
			if !copied {
				req.Messages = append([]llm.Message(nil), req.Messages...)
				copied = true
			}
			if !msgCopied {
				req.Messages[i].Content = append([]llm.ContentBlock(nil), m.Content...)
				msgCopied = true
			}
			req.Messages[i].Content[j].Thinking = ""
			rs = append(rs, replayed{msg: i, block: j, text: text})
		}
	}
	return req, rs
}

// dropLeakingThinking removes from out (in place: out shares nothing with
// the caller's request) the replayed signed thinking blocks whose cached
// text now holds an enrolled original. A message left without content gets
// that text transformed, unsigned, as a text block. dropped reports whether
// any block was removed.
func (w *wrapped) dropLeakingThinking(out llm.CompletionRequest, replay []replayed, prov Provenance) (llm.CompletionRequest, bool, error) {
	drop := map[int][]replayed{}
	for _, r := range replay {
		b, err := json.Marshal(r.text)
		if err != nil || len(w.e.LeakCheck(b)) > 0 {
			drop[r.msg] = append(drop[r.msg], r)
		}
	}
	if len(drop) == 0 {
		return out, false, nil
	}
	for i, rs := range drop {
		c := out.Messages[i].Content
		kept := make([]llm.ContentBlock, 0, len(c))
		for j, b := range c {
			if !slices.ContainsFunc(rs, func(r replayed) bool { return r.block == j }) {
				kept = append(kept, b)
			}
		}
		if len(kept) == 0 {
			var text strings.Builder
			for k, r := range rs {
				if k > 0 {
					text.WriteString("\n\n")
				}
				text.WriteString(r.text)
			}
			t, _, err := w.e.ToModelRequest(llm.CompletionRequest{Messages: []llm.Message{{Role: out.Messages[i].Role,
				Content: []llm.ContentBlock{{Type: llm.BlockText, Text: text.String()}}}}}, prov)
			if err != nil {
				return out, false, err
			}
			kept = t.Messages[0].Content
		}
		out.Messages[i].Content = kept
	}
	return out, true, nil
}

// auditUnresolved records a "response" event when a reply carried
// alias-shaped values that did not resolve (they reach the caller unchanged;
// the tool guard blocks their use).
func (w *wrapped) auditUnresolved(ctx context.Context, m meta, n int) error {
	if n == 0 {
		return nil
	}
	ev := w.event(m, "response")
	ev.Report.Flags = []string{"unresolved:" + strconv.Itoa(n)}
	if err := w.a.Record(ctx, ev); err != nil {
		return fmt.Errorf("membrane: audit failed: %w", err)
	}
	return nil
}

// Complete forwards the membraned request and de-aliases the reply message
// and text.
func (w *wrapped) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	out, m, err := w.prepare(ctx, req)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	msg, text, usage, err := w.inner.Complete(ctx, out)
	if err != nil {
		return msg, text, usage, err
	}
	for _, b := range msg.Content {
		if b.Signature != "" && b.Thinking != "" {
			w.sigs.put(b.Signature, b.Thinking)
		}
	}
	rm, u := w.e.ToRealMessage(msg)
	rt, u2 := w.e.ToReal(text)
	u = appendNew(u, u2...)
	if err := w.auditUnresolved(ctx, m, len(u)); err != nil {
		return llm.Message{}, "", usage, err
	}
	return rm, rt, usage, nil
}

// Stream forwards the membraned request and de-aliases the event stream
// (see streamDealiaser for the exact re-chunking contract).
func (w *wrapped) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		out, m, err := w.prepare(ctx, req)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		d := newStreamDealiaser(w.e, w.sigs)
		emit := func(evs []llm.StreamEvent) bool {
			for _, ev := range evs {
				if !yield(ev, nil) {
					return false
				}
			}
			return true
		}
		for ev, err := range w.inner.Stream(ctx, out) {
			if err != nil {
				if !emit(d.flush()) || !yield(ev, err) {
					return
				}
				continue
			}
			if !emit(d.push(ev)) {
				return
			}
		}
		if !emit(d.flush()) {
			return
		}
		if err := w.auditUnresolved(ctx, m, len(d.unresolved)); err != nil {
			yield(llm.StreamEvent{}, err)
		}
	}
}

// Signed-thinking cache bounds.
const (
	sigCacheEntries = 4096
	sigCacheBytes   = 64 << 20
)

// sigCache maps sha256(signature) to the alias-space thinking text the model
// returned with it (bounded LRU, in memory only).
type sigCache struct {
	mu       sync.Mutex
	max      int
	maxBytes int
	bytes    int
	ll       *list.List
	idx      map[[32]byte]*list.Element
}

type sigEntry struct {
	key  [32]byte
	text string
}

func newSigCache(maxEntries, maxBytes int) *sigCache {
	return &sigCache{max: maxEntries, maxBytes: maxBytes, ll: list.New(), idx: map[[32]byte]*list.Element{}}
}

func (c *sigCache) get(sig string) (string, bool) {
	k := sha256.Sum256([]byte(sig))
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.idx[k]
	if !ok {
		return "", false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*sigEntry).text, true
}

func (c *sigCache) put(sig, text string) {
	if len(text) > c.maxBytes {
		return
	}
	k := sha256.Sum256([]byte(sig))
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.idx[k]; ok {
		e := el.Value.(*sigEntry)
		c.bytes += len(text) - len(e.text)
		e.text = text
		c.ll.MoveToFront(el)
	} else {
		c.idx[k] = c.ll.PushFront(&sigEntry{key: k, text: text})
		c.bytes += len(text)
	}
	for c.ll.Len() > c.max || c.bytes > c.maxBytes {
		el := c.ll.Back()
		e := el.Value.(*sigEntry)
		c.ll.Remove(el)
		delete(c.idx, e.key)
		c.bytes -= len(e.text)
	}
}
