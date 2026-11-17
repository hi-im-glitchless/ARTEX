package membrane

import (
	"fmt"
	"net/netip"

	"github.com/Autumn-27/artex/db"
)

// ipBlock maps a real IPv4 prefix onto an alias prefix of the same width
// inside 240.0.0.0/4; host bits are preserved.
type ipBlock struct{ real, alias netip.Prefix }

// nonPublicV4 lists IPv4 ranges that are never aliased, besides the ones
// netip classifies (private, loopback, link-local, multicast, unspecified).
var nonPublicV4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking / fake-IP DNS
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"), // alias space itself, incl. broadcast
}

var aliasSpaceV6 = netip.MustParsePrefix("2001:db8::/32")

// isPublicIP reports whether a is a publicly routable address that must be
// aliased. Private, loopback, link-local (incl. 169.254.169.254), CGNAT, ULA,
// documentation and alias-space addresses are not.
func isPublicIP(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	if a.Is4() {
		for _, p := range nonPublicV4 {
			if p.Contains(a) {
				return false
			}
		}
		return true
	}
	return !aliasSpaceV6.Contains(a)
}

func addrToU32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32ToAddr(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// translate moves a from prefix `from` to the same offset inside `to`.
func translate(from, to netip.Prefix, a netip.Addr) netip.Addr {
	return u32ToAddr(addrToU32(to.Addr()) + (addrToU32(a) - addrToU32(from.Addr())))
}

func parseBlock(b db.MembraneBlock) (ipBlock, error) {
	r, err1 := netip.ParsePrefix(b.RealPrefix)
	a, err2 := netip.ParsePrefix(b.AliasPrefix)
	if err1 != nil || err2 != nil || !r.Addr().Is4() || !a.Addr().Is4() || r.Bits() != a.Bits() || r.Bits() != b.Bits {
		return ipBlock{}, fmt.Errorf("membrane store: corrupt ip block %q -> %q", b.RealPrefix, b.AliasPrefix)
	}
	return ipBlock{real: r.Masked(), alias: a.Masked()}, nil
}

func (s *Store) blocksSnapshot() []ipBlock {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]ipBlock(nil), s.blocks...)
}

// coveringBlock returns the block a real address maps through: the real
// address's own /24 block if allocated, else the most specific wider block
// containing it.
func coveringBlock(blocks []ipBlock, a netip.Addr) (ipBlock, bool) {
	p24 := netip.PrefixFrom(a, 24).Masked()
	var best ipBlock
	found := false
	for _, b := range blocks {
		if b.real == p24 {
			return b, true
		}
		if b.real.Bits() < 24 && b.real.Contains(a) && (!found || b.real.Bits() > best.real.Bits()) {
			best, found = b, true
		}
	}
	return best, found
}

// allocate persists a block for real (canonical) and records it in memory.
func (s *Store) allocate(real netip.Prefix) (ipBlock, error) {
	ap, err := s.p.AllocateMembraneBlock(real.String(), real.Bits())
	if err != nil {
		return ipBlock{}, fmt.Errorf("membrane: allocate block for %s: %w", real, err)
	}
	b, err := parseBlock(db.MembraneBlock{RealPrefix: real.String(), AliasPrefix: ap, Bits: real.Bits()})
	if err != nil {
		return ipBlock{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.blocks {
		if x.real == b.real {
			return x, nil
		}
	}
	s.blocks = append(s.blocks, b)
	return b, nil
}

// mapIPv4 computes the alias of a public IPv4, allocating its /24 block when
// no block covers it. Caller holds enrollMu.
func (s *Store) mapIPv4(a netip.Addr) (netip.Addr, error) {
	b, ok := coveringBlock(s.blocksSnapshot(), a)
	if !ok {
		var err error
		if b, err = s.allocate(netip.PrefixFrom(a, 24).Masked()); err != nil {
			return netip.Addr{}, err
		}
	}
	return translate(b.real, b.alias, a), nil
}

// IPv4Alias returns (and enrols) the alias of ip. Non-public addresses are
// returned unchanged. A real /24 keeps the block it was first given; an IP
// whose /24 has no block maps into the most specific seeded wider block that
// contains it, else a new /24 block is allocated. The last octet (host bits)
// is preserved.
func (s *Store) IPv4Alias(ip netip.Addr, prov Provenance) (netip.Addr, error) {
	ip = ip.Unmap()
	if !ip.Is4() {
		return netip.Addr{}, fmt.Errorf("membrane: %v is not IPv4", ip)
	}
	a, err := s.Enroll(KindIPv4, ip.String(), prov)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(a)
}

// SeedCIDR pre-allocates alias space for a scope CIDR. A prefix wider than
// /24 gets one aligned block of the same width (unless a seeded block already
// covers it); a /24 or narrower prefix ensures its /24 is mapped. Non-public
// and IPv6 prefixes are a no-op (IPv6 is aliased per address). prov is not
// recorded: blocks carry no provenance.
func (s *Store) SeedCIDR(p netip.Prefix, prov Provenance) error {
	_ = prov
	if !p.IsValid() || !p.Addr().Unmap().Is4() {
		return nil
	}
	p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()).Masked()
	if !isPublicIP(p.Addr()) {
		return nil
	}
	if p.Bits() < 8 {
		return fmt.Errorf("membrane: refusing to seed %s (wider than /8)", p)
	}
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	if p.Bits() >= 24 {
		_, err := s.mapIPv4(p.Addr())
		return err
	}
	for _, b := range s.blocksSnapshot() {
		if b.real.Bits() <= p.Bits() && b.real.Contains(p.Addr()) {
			return nil // already covered by an equal or wider block
		}
	}
	_, err := s.allocate(p)
	return err
}

// IPv4Real maps an alias address back to the real address: an exactly
// enrolled alias first, else the allocated block containing it (rule
// "IP inside an allocated alias block"). Not enrolled here; see ruling R4.
func (s *Store) IPv4Real(alias netip.Addr) (netip.Addr, bool) {
	alias = alias.Unmap()
	if !alias.Is4() {
		return netip.Addr{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e := s.aliasExact[alias.String()]; e != nil && e.kind == KindIPv4 {
		if r, err := netip.ParseAddr(e.original); err == nil {
			return r, true
		}
	}
	for _, b := range s.blocks {
		if b.alias.Contains(alias) {
			return translate(b.alias, b.real, alias), true
		}
	}
	return netip.Addr{}, false
}

// CIDRReal maps an alias prefix back to the real prefix when it is /24 or
// narrower and lies inside one allocated block, or exactly equals a seeded
// wider block.
func (s *Store) CIDRReal(alias netip.Prefix) (netip.Prefix, bool) {
	if !alias.IsValid() || !alias.Addr().Unmap().Is4() {
		return netip.Prefix{}, false
	}
	alias = netip.PrefixFrom(alias.Addr().Unmap(), alias.Bits()).Masked()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, b := range s.blocks {
		if alias.Bits() >= 24 && b.alias.Bits() <= alias.Bits() && b.alias.Contains(alias.Addr()) {
			return netip.PrefixFrom(translate(b.alias, b.real, alias.Addr()), alias.Bits()), true
		}
		if b.alias == alias {
			return b.real, true
		}
	}
	return netip.Prefix{}, false
}
