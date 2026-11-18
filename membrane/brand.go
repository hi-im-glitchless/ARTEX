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

// LabelHasClientKeyword reports whether label (a registrable domain's label,
// e.g. "acmebank-online") contains an enrolled org or product keyword under
// the dictionary's matching rules (R10 boundaries for short keywords). The
// seeder treats such a root as client space.
func (s *Store) LabelHasClientKeyword(label string) bool {
	return len(s.Dictionary().findAll(label, func(k Kind) bool {
		return k == KindOrg || k == KindProduct
	})) > 0
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
