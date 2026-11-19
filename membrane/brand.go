package membrane

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/publicsuffix"
)

// minBrandVariant is the shortest brand variant BrandVariants returns, in
// runes: shorter strings would alias ordinary words.
const minBrandVariant = 4

// BrandVariants infers the spellings a brand is written in (spec §7.1,
// cockpit _infer_terms). For a company name it returns the name with
// collapsed whitespace, the words joined, lowercase hyphenated and lowercase
// joined: "Acme Bank" -> {Acme Bank, AcmeBank, acme-bank, acmebank}. For a
// domain it returns the registrable label: "acmebank.pt" -> {acmebank}.
// Words are separated by whitespace, '-' and '_'. Variants shorter than 4
// runes are dropped; duplicates are removed (case-sensitively).
func BrandVariants(name string) []string {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	if label, ok := registrableLabel(name); ok {
		return keepVariants(label)
	}
	words := strings.FieldsFunc(name, func(r rune) bool {
		return unicode.IsSpace(r) || r == '-' || r == '_'
	})
	if len(words) == 0 {
		return nil
	}
	lower := make([]string, len(words))
	for i, w := range words {
		lower[i] = strings.ToLower(w)
	}
	return keepVariants(
		strings.Join(strings.Fields(name), " "),
		strings.Join(words, ""),
		strings.Join(lower, "-"),
		strings.Join(lower, ""),
	)
}

// registrableLabel returns the label left of the public suffix when name is a
// domain ("acmebank.co.uk" -> "acmebank"). ok is false for anything that is
// not a host name, and for a bare public suffix.
func registrableLabel(name string) (string, bool) {
	if !strings.Contains(name, ".") || strings.ContainsFunc(name, func(r rune) bool {
		return unicode.IsSpace(r) || r == '/' || r == '@' || r == ':'
	}) {
		return "", false
	}
	d := strings.TrimSuffix(strings.ToLower(name), ".")
	root, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return "", true // a bare public suffix ("co.uk"): no brand label
	}
	label, _, _ := strings.Cut(root, ".")
	return label, true
}

// LabelHasKeyword reports whether label (a registrable domain's label, e.g.
// "acmebank-online") contains one of keywords under the dictionary's
// matching rules (ruling R10): keywords of 5+ runes as substrings, shorter
// ones (3-4 runes) only as whole tokens. Keywords with spaces never occur
// in a label; shorter than 3 never match.
func LabelHasKeyword(label string, keywords []string) bool {
	label = strings.ToLower(label)
	for _, k := range keywords {
		k = strings.ToLower(strings.TrimSpace(k))
		n := utf8.RuneCountInString(k)
		if n < minLiteralLen || literalStoplist[k] || strings.ContainsFunc(k, unicode.IsSpace) {
			continue
		}
		if n > shortKeywordMax {
			if strings.Contains(label, k) {
				return true
			}
			continue
		}
		for _, tok := range strings.FieldsFunc(label, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		}) {
			if tok == k {
				return true
			}
		}
	}
	return false
}

func keepVariants(vs ...string) []string {
	var out []string
	for _, v := range vs {
		if utf8.RuneCountInString(v) < minBrandVariant {
			continue
		}
		dup := false
		for _, o := range out {
			if o == v {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, v)
		}
	}
	return out
}
