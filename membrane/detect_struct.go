package membrane

import (
	"net/netip"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// structDetector finds client hosts, public IPs, emails and personal
// identifiers by shape. Secrets live in secretDetector (detect_secrets.go).
//
// Go's regexp has no DFA, so each family first cuts the text into maximal
// runs of the bytes its values can contain (cheap byte loops) and runs its
// regexp only on runs that can hold a value. Boundary checks always look at
// the full text.
type structDetector struct{ s *Store }

func (d structDetector) Detect(text string) []Span {
	var out []Span
	out = d.domains(text, out)
	out = emails(text, out)
	out = ipv4s(text, out)
	out = ipv6s(text, out)
	forRuns(text, isNumberRunByte, func(s, e int) {
		if countDigits(text[s:e]) < minNumberDigits {
			return
		}
		out = ibans(text, s, e, out)
		out = cards(text, s, e, out)
		out = nifs(text, s, e, out)
		out = phones(text, s, e, out)
	})
	return out
}

func isASCIIAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }

func isWordByte(c byte) bool { return isASCIIAlnum(c) || c == '_' }

func isHostByte(c byte) bool { return isASCIIAlnum(c) || c == '-' }

func isHexByte(c byte) bool {
	return isDigitByte(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// byteBefore and byteAfter return the neighbour byte of text[s:e], or 0 at an
// edge.
func byteBefore(text string, s int) byte {
	if s > 0 {
		return text[s-1]
	}
	return 0
}

func byteAfter(text string, e int) byte {
	if e < len(text) {
		return text[e]
	}
	return 0
}

func rawSpan(text string, s, e int, k Kind) Span {
	return Span{Start: s, End: e, Kind: k, Value: text[s:e]}
}

// forRuns calls fn for every maximal run text[s:e] of bytes in class.
func forRuns(text string, class func(byte) bool, fn func(s, e int)) {
	for i := 0; i < len(text); {
		if !class(text[i]) {
			i++
			continue
		}
		j := i + 1
		for j < len(text) && class(text[j]) {
			j++
		}
		fn(i, j)
		i = j
	}
}

// findIn runs re over text[s:e] and returns submatch indices into text.
func findIn(re *regexp.Regexp, text string, s, e int) [][]int {
	ms := re.FindAllStringSubmatchIndex(text[s:e], -1)
	for _, m := range ms {
		for i := range m {
			if m[i] >= 0 {
				m[i] += s
			}
		}
	}
	return ms
}

// domainTokenRE is middlehack's DOMAIN_TOKEN_RE without its lookarounds,
// which are checked in code: at least two labels, alphabetic last label.
var domainTokenRE = regexp.MustCompile(`(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}`)

// domains reports hosts equal to or under an enrolled root. Hosts under any
// other root (third parties) are never reported: enrolling them would make
// their root a client root. Client keywords inside such hosts are dictionary
// hits instead.
func (d structDetector) domains(text string, out []Span) []Span {
	if d.s == nil {
		return out
	}
	roots := d.s.Roots()
	if len(roots) == 0 {
		return out
	}
	known := make(map[string]bool, len(roots))
	for _, r := range roots {
		known[r] = true
	}
	inHost := func(c byte) bool { return isHostByte(c) || c == '.' }
	forRuns(text, inHost, func(s, e int) {
		if strings.IndexByte(text[s:e], '.') < 0 {
			return
		}
		for _, m := range findIn(domainTokenRE, text, s, e) {
			if isHostByte(byteBefore(text, m[0])) || isHostByte(byteAfter(text, m[1])) {
				continue
			}
			host := strings.ToLower(text[m[0]:m[1]])
			if host == "example" || strings.HasSuffix(host, ".example") {
				continue // alias space
			}
			root, err := publicsuffix.EffectiveTLDPlusOne(host)
			if err != nil || !known[root] {
				continue
			}
			out = append(out, rawSpan(text, m[0], m[1], KindDomain))
		}
	})
	return out
}

var emailRE = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*\.[A-Za-z]{2,24}`)

func isEmailByte(c byte) bool {
	return isHostByte(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '@'
}

// emails reports every email address outside the alias space (the local
// part is personal data whatever the domain).
func emails(text string, out []Span) []Span {
	forRuns(text, isEmailByte, func(s, e int) {
		if strings.IndexByte(text[s:e], '@') < 0 {
			return
		}
		for _, m := range findIn(emailRE, text, s, e) {
			if isHostByte(byteAfter(text, m[1])) {
				continue
			}
			v := strings.ToLower(text[m[0]:m[1]])
			if strings.HasSuffix(v, ".example") || inURLUserinfo(text, m[0]) {
				continue
			}
			out = append(out, rawSpan(text, m[0], m[1], KindEmail))
		}
	})
	return out
}

// maxUserinfoLookback bounds the backward scan of inURLUserinfo so emails in
// a long run without separators stay linear.
const maxUserinfoLookback = 512

// inURLUserinfo reports whether position i is inside the authority of a URL
// (scheme://user:pass@host): the '@' there ends credentials, not an email
// address. Those are userinfoSecrets' spans.
func inURLUserinfo(text string, i int) bool {
	lo := max(0, i-maxUserinfoLookback)
	ls := lo + strings.LastIndexAny(text[lo:i], " \t\r\n\"'<>") + 1
	prefix := text[ls:i]
	j := strings.Index(prefix, "://")
	return j >= 0 && !strings.ContainsAny(prefix[j+3:], "/?#")
}

// ipv4s reports public dotted quads. Like middlehack's IPV4_RE, a quad that
// is part of a longer dotted number (1.2.3.4.5) is ignored; a trailing
// sentence dot is allowed.
func ipv4s(text string, out []Span) []Span {
	forRuns(text, func(c byte) bool { return isDigitByte(c) || c == '.' }, func(s, e int) {
		for e > s && text[e-1] == '.' {
			e--
		}
		if e-s < 7 || strings.Count(text[s:e], ".") != 3 {
			return
		}
		a, err := netip.ParseAddr(text[s:e])
		if err != nil || !a.Is4() || !isPublicIP(a) {
			return
		}
		out = append(out, rawSpan(text, s, e, KindIPv4))
	})
	return out
}

// ipv6s reports public IPv6 addresses. A candidate must stand alone (no
// letter, digit or '_' around it, so std::cout is not an address) and
// contain a decimal digit. IPv4-mapped addresses are left to ipv4s.
func ipv6s(text string, out []Span) []Span {
	forRuns(text, func(c byte) bool { return isHexByte(c) || c == ':' || c == '.' }, func(s, e int) {
		if strings.Count(text[s:e], ":") < 2 || isWordByte(byteBefore(text, s)) || isWordByte(byteAfter(text, e)) {
			return
		}
		a, err := netip.ParseAddr(text[s:e])
		for err != nil && e > s && (text[e-1] == '.' || text[e-1] == ':') {
			e--
			a, err = netip.ParseAddr(text[s:e])
		}
		if err != nil || !a.Is6() || a.Is4In6() || !strings.ContainsAny(text[s:e], "0123456789") || !isPublicIP(a) {
			return
		}
		out = append(out, rawSpan(text, s, e, KindIPv6))
	})
	return out
}

// Number-shaped identifiers (IBAN, card, NIF, phone) live in runs of digits,
// capitals and separators holding at least minNumberDigits digits.
const minNumberDigits = 8

func isNumberRunByte(c byte) bool {
	return isDigitByte(c) || c >= 'A' && c <= 'Z' || c == ' ' || c == '+' || c == '.' || c == '-'
}

func countDigits(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if isDigitByte(s[i]) {
			n++
		}
	}
	return n
}

// standsAlone reports whether text[s:e] has no word byte on either side.
func standsAlone(text string, s, e int) bool {
	return !isWordByte(byteBefore(text, s)) && !isWordByte(byteAfter(text, e))
}

var ibanRE = regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`)

// ibans reports IBANs with a valid ISO 13616 mod-97 check.
func ibans(text string, s, e int, out []Span) []Span {
	for _, m := range findIn(ibanRE, text, s, e) {
		if standsAlone(text, m[0], m[1]) && ibanValid(strings.ReplaceAll(text[m[0]:m[1]], " ", "")) {
			out = append(out, rawSpan(text, m[0], m[1], KindIBAN))
		}
	}
	return out
}

func ibanValid(s string) bool {
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	s = s[4:] + s[:4]
	rem := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			rem = (rem*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			rem = (rem*100 + int(c-'A'+10)) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// cardRE allows single space or dash separators; the first digit (2-6)
// keeps millisecond timestamps and similar counters out.
var cardRE = regexp.MustCompile(`\b[2-6][0-9](?:[ -]?[0-9]){11,17}\b`)

// cards reports Luhn-valid card numbers of 13-19 digits. When the greedy
// match swallows a following number, shorter prefixes ending at a separator
// are tried.
func cards(text string, rs, re int, out []Span) []Span {
	for _, m := range findIn(cardRE, text, rs, re) {
		s := m[0]
		if isWordByte(byteBefore(text, s)) {
			continue
		}
		for e := m[1]; e > s; e-- {
			if e == m[1] {
				if isWordByte(byteAfter(text, e)) {
					continue
				}
			} else if text[e] != ' ' && text[e] != '-' {
				continue
			}
			if !isDigitByte(text[e-1]) {
				continue
			}
			digits := onlyDigits(text[s:e])
			if len(digits) < 13 {
				break
			}
			if len(digits) <= 19 && luhnValid(digits) {
				out = append(out, rawSpan(text, s, e, KindCard))
				break
			}
		}
	}
	return out
}

func onlyDigits(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if isDigitByte(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func luhnValid(d string) bool {
	sum := 0
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if (len(d)-1-i)%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

var nifRE = regexp.MustCompile(`\b[1235689][0-9]{8}\b`)

// nifs reports Portuguese NIFs (9 digits, mod-11 check digit).
func nifs(text string, s, e int, out []Span) []Span {
	for _, m := range findIn(nifRE, text, s, e) {
		if standsAlone(text, m[0], m[1]) && nifValid(text[m[0]:m[1]]) {
			out = append(out, rawSpan(text, m[0], m[1], KindNIF))
		}
	}
	return out
}

func nifValid(d string) bool {
	sum := 0
	for i := range 8 {
		sum += int(d[i]-'0') * (9 - i)
	}
	check := 11 - sum%11
	if check >= 10 {
		check = 0
	}
	return int(d[8]-'0') == check
}

// Phones: Portuguese numbers (optional +351/00351, mobile 91/92/93/96 or
// landline 2x) and any other '+'-prefixed international number.
var (
	phonePTRE   = regexp.MustCompile(`(?:(?:\+|00)351[ .-]?)?(?:9[1236]|2[0-9])[0-9][ .-]?[0-9]{3}[ .-]?[0-9]{3}`)
	phoneIntlRE = regexp.MustCompile(`\+[1-9][0-9]{0,2}(?:[ .-]?[0-9]){7,12}`)
)

func phones(text string, s, e int, out []Span) []Span {
	for _, re := range []*regexp.Regexp{phonePTRE, phoneIntlRE} {
		for _, m := range findIn(re, text, s, e) {
			b, a := byteBefore(text, m[0]), byteAfter(text, m[1])
			if isASCIIAlnum(b) || b == '+' || b == '.' || isASCIIAlnum(a) {
				continue
			}
			out = append(out, rawSpan(text, m[0], m[1], KindPhone))
		}
	}
	return out
}
