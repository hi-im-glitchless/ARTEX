package agent

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
)

// MembraneEnv is the only override of the identity membrane: the exact value
// "off" disables it for every profile (spec §9.4). It needs host access, so
// it is not a UI switch.
const MembraneEnv = "ARTEX_MEMBRANE"

// ErrMembraneNotInitialised is returned by NewProvider when the base URL
// needs the membrane but the config carries no engine or auditor (for
// example because the store failed to open). No request is possible.
var ErrMembraneNotInitialised = errors.New("membrane required but not initialised")

// overrideRefused is set when ARTEX_MEMBRANE=off could not be audited: the
// override then does not take effect (spec §10: every unmembraned run must
// be on record).
var overrideRefused atomic.Bool

// MembraneOverride reports whether ARTEX_MEMBRANE=off is set and in effect
// (not refused by SetMembraneOverrideRefused).
func MembraneOverride() bool {
	return MembraneOverrideRequested() && !overrideRefused.Load()
}

// MembraneOverrideRequested reports whether ARTEX_MEMBRANE=off is set, in
// effect or not.
func MembraneOverrideRequested() bool { return os.Getenv(MembraneEnv) == "off" }

// SetMembraneOverrideRefused makes the override ineffective (true) or lets
// it take effect again (false). The server refuses an override it cannot
// audit; remote providers then need the membrane and fail closed.
func SetMembraneOverrideRefused(refused bool) { overrideRefused.Store(refused) }

// membraneRequiredFn is the test hook NewProvider consults (tests force it
// to true for a local httptest server).
var membraneRequiredFn = MembraneRequired

// refuseUntrustedRedirect is the CheckRedirect of providers built without the
// membrane: a redirect may only lead to another host that would not need the
// membrane either (same rule as MembraneRequired, so the override allows all).
func refuseUntrustedRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("llm: stopped after 10 redirects")
	}
	if membraneRequiredFn(req.URL.String()) {
		return errors.New("llm: redirect from a local model endpoint to a non-local host refused (it would bypass the identity membrane)")
	}
	return nil
}

// MembraneRequired reports whether a provider at baseURL must go through the
// membrane. Trust is derived, not set: it is false only when the host is a
// literal loopback, RFC 1918 or ULA IP, or "localhost", or when the override
// is active. Hostnames other than localhost are never resolved, an empty base
// URL (the provider's default endpoint) is remote, and anything unparsable is
// remote (fail closed).
func MembraneRequired(baseURL string) bool {
	if MembraneOverride() {
		return false
	}
	raw := strings.TrimSpace(baseURL)
	if raw == "" {
		return true
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return true
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return true
	}
	addr = addr.Unmap()
	// IsPrivate covers 10/8, 172.16/12, 192.168/16 and fc00::/7 (ULA).
	return !(addr.IsLoopback() || addr.IsPrivate())
}
