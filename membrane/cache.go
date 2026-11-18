package membrane

import (
	"container/list"
	"sync"
)

// Cache bounds: replayed conversation history is mostly cache hits, so the
// engine does not rescan it on every request.
const (
	cacheMaxEntries = 4096
	cacheMaxBytes   = 64 << 20 // total cached input + output bytes
)

// lru is a bounded LRU keyed by sha256 with a byte budget. Each entry
// records the store generation it is valid at and its input text, so a
// lookup after a generation change can be revalidated against the changes
// since (delta.go) instead of recomputed.
type lru[V any] struct {
	mu    sync.Mutex
	ll    *list.List
	m     map[[32]byte]*list.Element
	bytes int
	size  func(in string, v V) int
}

type lruEntry[V any] struct {
	key [32]byte
	gen uint64
	in  string
	val V
	n   int
}

func newLRU[V any](size func(in string, v V) int) *lru[V] {
	return &lru[V]{ll: list.New(), m: map[[32]byte]*list.Element{}, size: size}
}

// get returns the entry for key whatever its generation.
func (c *lru[V]) get(key [32]byte) (gen uint64, val V, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[key]
	if !ok {
		return 0, val, false
	}
	ce := el.Value.(*lruEntry[V])
	c.ll.MoveToFront(el)
	return ce.gen, ce.val, true
}

// revalidate moves the entry for key from generation from to to (no-op if
// it changed meanwhile).
func (c *lru[V]) revalidate(key [32]byte, from, to uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		if ce := el.Value.(*lruEntry[V]); ce.gen == from && to > from {
			ce.gen = to
		}
	}
}

func (c *lru[V]) put(key [32]byte, gen uint64, in string, val V) {
	n := c.size(in, val)
	if n > cacheMaxBytes/16 {
		return // one huge text must not flush the cache
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		ce := el.Value.(*lruEntry[V])
		c.bytes += n - ce.n
		ce.gen, ce.in, ce.val, ce.n = gen, in, val, n
		c.ll.MoveToFront(el)
	} else {
		c.m[key] = c.ll.PushFront(&lruEntry[V]{key: key, gen: gen, in: in, val: val, n: n})
		c.bytes += n
	}
	for c.ll.Len() > cacheMaxEntries || c.bytes > cacheMaxBytes {
		el := c.ll.Back()
		ce := el.Value.(*lruEntry[V])
		c.ll.Remove(el)
		delete(c.m, ce.key)
		c.bytes -= ce.n
	}
}

func (c *lru[V]) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}

// toModelCache caches ToModel results keyed by sha256(role, provenance,
// text).
type toModelCache struct{ *lru[tmResult] }

type tmResult struct {
	out string
	rep Report
}

// cached is a toModelCache lookup.
type cached struct {
	gen uint64
	out string
	rep Report
}

func newToModelCache() *toModelCache {
	return &toModelCache{newLRU(func(in string, v tmResult) int { return len(in) + len(v.out) })}
}

func (c *toModelCache) get(key [32]byte) (cached, bool) {
	g, v, ok := c.lru.get(key)
	if !ok {
		return cached{}, false
	}
	return cached{gen: g, out: v.out, rep: v.rep.clone()}, true
}

func (c *toModelCache) put(key [32]byte, gen uint64, in, out string, rep Report) {
	c.lru.put(key, gen, in, tmResult{out: out, rep: rep.clone()})
}

// leakCache caches LeakCheck hits per body segment keyed by sha256(segment);
// offsets are relative to the segment.
type leakCache struct{ *lru[[]LeakHit] }

func newLeakCache() *leakCache {
	return &leakCache{newLRU(func(in string, v []LeakHit) int { return len(in) + 16*len(v) })}
}
