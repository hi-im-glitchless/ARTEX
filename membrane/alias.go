package membrane

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math/rand/v2"
	"net/netip"
	"strings"
)

// Deriver deterministically derives aliases from a secret key.
type Deriver struct{ key []byte }

// NewDeriver returns a Deriver using key (copied) as the HMAC key.
func NewDeriver(key []byte) *Deriver {
	return &Deriver{key: append([]byte(nil), key...)}
}

func (d *Deriver) mac(parts ...string) [32]byte {
	h := hmac.New(sha256.New, d.key)
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// RootDomain returns a stable alias such as "a1b2c3.example" for a root domain.
// Matching is case-insensitive.
func (d *Deriver) RootDomain(root string) string {
	s := d.mac("root-domain", strings.ToLower(strings.TrimSpace(root)))
	return hex.EncodeToString(s[:3]) + ".example"
}

// Keyword returns an alias such as "ORG-7f2c". Collisions are resolved by the store.
func (d *Deriver) Keyword(kind Kind, term string) string {
	s := d.mac("keyword", string(kind), strings.ToLower(strings.TrimSpace(term)))
	return strings.ToUpper(string(kind)) + "-" + hex.EncodeToString(s[:2])
}

// EmailLocal returns an alias such as "user-5e1a" for an email local part.
func (d *Deriver) EmailLocal(local string) string {
	s := d.mac("email-local", strings.ToLower(local))
	return "user-" + hex.EncodeToString(s[:2])
}

// FormatPreserving returns a value of the same length and character classes as
// original (lower->lower, upper->upper, digit->digit, others kept) that differs
// from it. For KindCard the result keeps a valid Luhn check digit.
func (d *Deriver) FormatPreserving(kind Kind, original string) string {
	seed := d.mac("format-preserving", string(kind), original)
	rng := rand.New(rand.NewChaCha8(seed))
	rs := []rune(original)
	out := make([]rune, len(rs))
	for i, r := range rs {
		out[i] = substitute(rng, r)
	}
	card := kind == KindCard
	if card {
		fixLuhn(out)
	}
	if string(out) == original {
		perturb(out, card)
	}
	return string(out)
}

func substitute(rng *rand.Rand, r rune) rune {
	switch {
	case r >= 'a' && r <= 'z':
		return 'a' + rune(rng.IntN(26))
	case r >= 'A' && r <= 'Z':
		return 'A' + rune(rng.IntN(26))
	case r >= '0' && r <= '9':
		return '0' + rune(rng.IntN(10))
	}
	return r
}

func isDigit(r rune) bool { return r >= '0' && r <= '9' }

// perturb deterministically rotates the first eligible character within its
// class. For cards it skips the check digit and then re-fixes it.
func perturb(out []rune, card bool) {
	last := -1
	if card {
		for i := len(out) - 1; i >= 0; i-- {
			if isDigit(out[i]) {
				last = i
				break
			}
		}
	}
	for i, r := range out {
		if card && (i == last || !isDigit(r)) {
			continue
		}
		switch {
		case r >= 'a' && r <= 'z':
			out[i] = 'a' + (r-'a'+1)%26
		case r >= 'A' && r <= 'Z':
			out[i] = 'A' + (r-'A'+1)%26
		case isDigit(r):
			out[i] = '0' + (r-'0'+1)%10
		default:
			continue
		}
		break
	}
	if card {
		fixLuhn(out)
	}
}

// fixLuhn sets the last digit so the digit sequence passes the Luhn check.
func fixLuhn(out []rune) {
	var idx []int
	for i, r := range out {
		if isDigit(r) {
			idx = append(idx, i)
		}
	}
	if len(idx) < 2 {
		return
	}
	sum := 0
	// Walk the payload (all but the check digit) right to left; the rightmost
	// payload digit is doubled.
	for n, k := 0, len(idx)-2; k >= 0; n, k = n+1, k-1 {
		v := int(out[idx[k]] - '0')
		if n%2 == 0 {
			v *= 2
			if v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	out[idx[len(idx)-1]] = rune('0' + (10-sum%10)%10)
}

// IPv6 deterministically maps an IPv6 address into the documentation prefix
// 2001:db8::/32 using HMAC-derived host bits. Collisions are the caller's concern.
func (d *Deriver) IPv6(ip netip.Addr) netip.Addr {
	s := d.mac("ipv6", ip.Unmap().String())
	var b [16]byte
	b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, 0xb8
	copy(b[4:], s[:12])
	return netip.AddrFrom16(b)
}
