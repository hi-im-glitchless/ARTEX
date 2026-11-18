package membrane

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"sync"

	"github.com/Autumn-27/artex/db"
)

// overlayPersistence reads the mapping from a base Persistence and keeps
// every write in memory (ruling R7). It backs dry-run engine views and
// read-only stores: nothing it is given ever reaches the base.
type overlayPersistence struct {
	base Persistence

	mu       sync.Mutex
	nextID   int64
	rows     map[string]db.MembraneEntry // kind+"\x00"+hmac of rows written here
	blocks   []db.MembraneBlock          // base blocks (loaded lazily) + local
	blocksOK bool
}

func newOverlay(base Persistence) *overlayPersistence {
	return &overlayPersistence{base: base, rows: map[string]db.MembraneEntry{}}
}

func (o *overlayPersistence) InsertMembraneEntry(e *db.MembraneEntry) (db.MembraneEntry, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	key := e.Kind + "\x00" + e.OriginalHMAC
	if x, ok := o.rows[key]; ok {
		x.CompanyIDs = mergeInt64s(x.CompanyIDs, e.CompanyIDs)
		x.TaskIDs = mergeInt64s(x.TaskIDs, e.TaskIDs)
		o.rows[key] = x
		return x, nil
	}
	n := *e
	o.nextID--
	n.ID = o.nextID // negative: never a database id
	if n.Source == "" {
		n.Source = "auto"
	}
	n.CompanyIDs = slices.Clone(e.CompanyIDs)
	n.TaskIDs = slices.Clone(e.TaskIDs)
	o.rows[key] = n
	return n, nil
}

func (o *overlayPersistence) UpdateMembraneEntryAlias(int64, string) error { return nil }

func (o *overlayPersistence) ListMembraneEntries() ([]db.MembraneEntry, error) {
	o.mu.Lock()
	local := len(o.rows)
	o.mu.Unlock()
	if local > 0 {
		// Reloading from the base would drop the local rows; the store only
		// reloads after a failed insert, which the overlay never returns.
		return nil, errors.New("membrane overlay: reload after local writes is not supported")
	}
	return o.base.ListMembraneEntries()
}

func (o *overlayPersistence) ListMembraneBlocks() ([]db.MembraneBlock, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.loadBlocksLocked(); err != nil {
		return nil, err
	}
	return slices.Clone(o.blocks), nil
}

func (o *overlayPersistence) loadBlocksLocked() error {
	if o.blocksOK {
		return nil
	}
	bs, err := o.base.ListMembraneBlocks()
	if err != nil {
		return err
	}
	o.blocks, o.blocksOK = append(o.blocks, bs...), true
	return nil
}

// AllocateMembraneBlock mirrors db.AllocateMembraneBlock (the lowest
// bits-aligned block in 240.0.0.0/4 not overlapping an allocated one), so
// a dry run predicts the block the real run allocates, unless another
// allocation happens in between.
func (o *overlayPersistence) AllocateMembraneBlock(realPrefix string, bits int) (string, error) {
	if bits < 4 || bits > 32 {
		return "", fmt.Errorf("membrane block: unsupported prefix length %d", bits)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := o.loadBlocksLocked(); err != nil {
		return "", err
	}
	for _, b := range o.blocks {
		if b.RealPrefix == realPrefix {
			return b.AliasPrefix, nil
		}
	}
	type span struct{ lo, hi uint64 }
	used := make([]span, 0, len(o.blocks))
	for _, b := range o.blocks {
		p, err := netip.ParsePrefix(b.AliasPrefix)
		if err != nil || !p.Addr().Is4() {
			return "", errors.New("membrane block: corrupt alias prefix")
		}
		lo := uint64(addrToU32(p.Addr()))
		used = append(used, span{lo, lo + 1<<(32-uint(p.Bits())) - 1})
	}
	size := uint64(1) << (32 - uint(bits))
	for start := uint64(0xF0000000); start+size-1 <= 0xFFFFFFFF; start += size {
		end := start + size - 1
		clash := false
		for _, u := range used {
			if start <= u.hi && u.lo <= end {
				clash = true
				break
			}
		}
		if !clash {
			a := fmt.Sprintf("%d.%d.%d.%d/%d", start>>24&0xFF, start>>16&0xFF, start>>8&0xFF, start&0xFF, bits)
			o.blocks = append(o.blocks, db.MembraneBlock{RealPrefix: realPrefix, AliasPrefix: a, Bits: bits})
			return a, nil
		}
	}
	return "", errors.New("membrane block: 240.0.0.0/4 alias space exhausted")
}

func mergeInt64s(a, b []int64) []int64 {
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// OpenReadOnlyStore opens the mapping like OpenStore, but every write
// (enrolment, re-mint heal, block allocation) stays in memory: for offline
// tools such as `artex membrane verify`, which must not change the table.
func OpenReadOnlyStore(p Persistence, encKey, hmacKey []byte) (*Store, error) {
	return OpenStore(newOverlay(p), encKey, hmacKey)
}

// dryClone returns an in-memory copy of s whose writes go to an overlay:
// the same keys, entries (deep-copied), blocks and model-known marks. It
// takes enrollMu so the snapshot sits between enrolments.
func (s *Store) dryClone() *Store {
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := &Store{
		p:          newOverlay(s.p),
		aead:       s.aead,
		indexKey:   s.indexKey,
		deriveKey:  s.deriveKey,
		deriver:    s.deriver,
		modelKnown: maps.Clone(s.modelKnown),
	}
	c.keywordAlias = s.keywordAlias // pure function of the shared keys
	c.resetMaps()
	keys := make([]string, 0, len(s.byKey))
	for k := range s.byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic index order (first wins in fold maps)
	for _, k := range keys {
		e := s.byKey[k]
		ne := *e
		ne.retired = slices.Clone(e.retired)
		ne.companyIDs = slices.Clone(e.companyIDs)
		ne.taskIDs = slices.Clone(e.taskIDs)
		c.indexEntry(&ne)
	}
	maps.Copy(c.quarantined, s.quarantined)
	c.blocks = slices.Clone(s.blocks)
	c.dict, c.dictDirty = nil, true
	return c
}

// WithDryRun returns an engine view over an in-memory copy of the store
// (ruling R7): ToModel derives the aliases a real run would mint for new
// values, with the same derivation, but persists nothing, never changes the
// live store or its generation, and uses its own cache. A dry alias can
// differ from the later real one only when another enrolment takes the same
// alias first (collision re-derive) or allocates the next IPv4 block first.
// The view is meant for one preview and then dropped.
func (e *Engine) WithDryRun() *Engine {
	c := e.s.dryClone()
	d := &Engine{s: c, p: e.p.rebind(c), cache: newToModelCache(), rejected: map[string]struct{}{}}
	e.rejMu.Lock()
	maps.Copy(d.rejected, e.rejected)
	e.rejMu.Unlock()
	return d
}

// rebind returns a copy of p whose store-backed detectors use s.
func (p *Pipeline) rebind(s *Store) *Pipeline {
	dets := make([]Detector, len(p.dets))
	for i, d := range p.dets {
		if _, ok := d.(structDetector); ok {
			d = structDetector{s}
		}
		dets[i] = d
	}
	return &Pipeline{store: s, dets: dets}
}

// Store returns the store the engine rewrites with (for a dry-run view, its
// in-memory copy).
func (e *Engine) Store() *Store { return e.s }

// Reload rebuilds the in-memory index from persistence, for example after a
// company purge deleted rows. It waits for in-flight enrolments, so none is
// lost by the swap.
func (s *Store) Reload() error {
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	return s.reload()
}

// AliasSpan locates one minted alias in a text.
type AliasSpan struct {
	Start, End int
	Kind       Kind
}

// AliasSpans returns the non-overlapping ranges of minted aliases in t,
// ordered by Start: exact aliases (longest match) and alias-shaped tokens
// that resolve (hosts under a minted root, addresses in allocated blocks).
// For a ToModel output these are the replaced values (and any alias the
// input already carried).
func (e *Engine) AliasSpans(t string) []AliasSpan {
	var cs []aliasCand
	for _, m := range e.s.ReverseDictionary().FindAll(t) {
		if e.hostSuffixOK(t, m) {
			cs = append(cs, aliasCand{AliasSpan{m.Start, m.End, m.Kind}, 0})
		}
	}
	for _, sh := range scanShapes(t) {
		var k Kind
		switch sh.kind {
		case shapeHost:
			if e.underMintedDomain(sh.text) {
				k = KindDomain
			}
		case shapeIPv4:
			if _, ok := e.s.IPv4Real(netip.MustParseAddr(sh.text)); ok {
				k = KindIPv4
			}
		case shapeCIDR:
			if _, ok := e.s.CIDRReal(netip.MustParsePrefix(sh.text)); ok {
				k = KindIPv4
			}
		default:
			if _, kk, ok := e.s.OriginalFor(sh.text); ok {
				k = kk
			}
		}
		if k != "" {
			cs = append(cs, aliasCand{AliasSpan{sh.Start, sh.End, k}, 1})
		}
	}
	kept := pickLongest(cs, len(t))
	out := make([]AliasSpan, len(kept))
	for i, c := range kept {
		out[i] = c.AliasSpan
	}
	return out
}

type aliasCand struct {
	AliasSpan
	prio int
}

func (c aliasCand) bounds() (int, int, int) { return c.Start, c.End, c.prio }
