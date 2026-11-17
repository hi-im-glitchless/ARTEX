package membrane

import (
	"container/list"
	"sync"
)

// Cache bounds: replayed conversation history is mostly cache hits, so the
// engine does not rescan it on every request.
const (
	cacheMaxEntries = 4096
	cacheMaxBytes   = 64 << 20 // total cached output bytes
)

// toModelCache is a bounded LRU of ToModel results keyed by sha256(text). An
// entry is valid only for the generation it was computed at.
type toModelCache struct {
	mu    sync.Mutex
	ll    *list.List
	m     map[[32]byte]*list.Element
	bytes int
}

type cacheEntry struct {
	key [32]byte
	gen uint64
	out string
	rep Report
}

func newToModelCache() *toModelCache {
	return &toModelCache{ll: list.New(), m: map[[32]byte]*list.Element{}}
}

func (c *toModelCache) get(key [32]byte, gen uint64) (string, Report, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[key]
	if !ok {
		return "", Report{}, false
	}
	ce := el.Value.(*cacheEntry)
	if ce.gen != gen {
		return "", Report{}, false
	}
	c.ll.MoveToFront(el)
	return ce.out, ce.rep.clone(), true
}

func (c *toModelCache) put(key [32]byte, gen uint64, out string, rep Report) {
	if len(out) > cacheMaxBytes/16 {
		return // one huge text must not flush the cache
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		ce := el.Value.(*cacheEntry)
		c.bytes += len(out) - len(ce.out)
		ce.gen, ce.out, ce.rep = gen, out, rep.clone()
		c.ll.MoveToFront(el)
	} else {
		c.m[key] = c.ll.PushFront(&cacheEntry{key: key, gen: gen, out: out, rep: rep.clone()})
		c.bytes += len(out)
	}
	for c.ll.Len() > cacheMaxEntries || c.bytes > cacheMaxBytes {
		el := c.ll.Back()
		ce := el.Value.(*cacheEntry)
		c.ll.Remove(el)
		delete(c.m, ce.key)
		c.bytes -= len(ce.out)
	}
}

func (c *toModelCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
