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
	"strconv"
	"strings"
	"sync"

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

// engineAPI is the part of *Engine the decorator uses; tests substitute a
// faulty engine to prove the leak check blocks.
type engineAPI interface {
	ToModelRequest(req llm.CompletionRequest, prov Provenance) (llm.CompletionRequest, Report, error)
	LeakCheck(serialised []byte) []LeakHit
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
	w := &wrapped{inner: inner, e: e, a: a, profile: profile, sigs: newSigCache(sigCacheEntries, sigCacheBytes)}
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

// provenanceFrom: the task id from llmrec (numeric ids only), source "auto".
// Company ids are seeded by the syncer, not here.
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
	in, replay := w.stripSignedThinking(req)
	out, rep, err := w.e.ToModelRequest(in, provenanceFrom(ctx))
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
	ev.Report = rep
	if hits := w.e.LeakCheck(body); len(hits) > 0 {
		return llm.CompletionRequest{}, m, block(leakReason(hits), ErrLeakBlocked)
	}
	sum := sha256.Sum256(body)
	ev.RequestSHA256 = hex.EncodeToString(sum[:])
	if err := w.a.Record(ctx, ev); err != nil {
		return llm.CompletionRequest{}, m, fmt.Errorf("membrane: audit failed, request not sent: %w", err)
	}
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
