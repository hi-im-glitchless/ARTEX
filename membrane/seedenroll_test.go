package membrane

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// seedEnroll is Enroll as the seeder uses it for a value the test declares
// as client data: a domain's (or a non-free-mail email's) root is opted in
// with EnrollRoot first, since Enroll never mints a root implicitly.
func (s *Store) seedEnroll(kind Kind, original string, prov Provenance) (string, error) {
	var host string
	switch kind {
	case KindDomain:
		host = original
	case KindEmail:
		if i := strings.LastIndexByte(original, '@'); i >= 0 {
			host = original[i+1:]
		}
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host != "" && !freeMailDomains[host] {
		if root, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil && !strings.ContainsAny(root, " \t") {
			if _, err := s.EnrollRoot(root, prov); err != nil {
				return "", err
			}
		}
	}
	return s.Enroll(kind, original, prov)
}
