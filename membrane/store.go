package membrane

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Persistence is the subset of *db.DB the Store needs.
type Persistence interface {
	InsertMembraneEntry(e *db.MembraneEntry) (db.MembraneEntry, error)
	ListMembraneEntries() ([]db.MembraneEntry, error)
	AllocateMembraneBlock(realPrefix string, bits int) (aliasPrefix string, err error)
	ListMembraneBlocks() ([]db.MembraneBlock, error)
}

// Provenance records who caused an enrolment. Source is one of the
// membrane_entries source values (seed, auto, operator, model_known); empty
// means "auto".
type Provenance struct {
	CompanyIDs []int64
	TaskIDs    []int64
	Source     string
}

// Domain-separated subkeys of the HMAC key (ruling R1).
const (
	deriveKeyLabel = "artex-membrane-derive-v1"
	indexKeyLabel  = "artex-membrane-index-v1"
	rehashLabel    = "artex-membrane-rehash-v1"
	maxMintAttempt = 64
)

// minLiteralLen and literalStoplist keep ambiguous originals out of the
// dictionary automaton (ruling R3). They stay in the store for exact lookup.
const minLiteralLen = 3

var literalStoplist = map[string]bool{
	"admin": true, "root": true, "test": true, "user": true, "guest": true,
	"demo": true, "api": true, "www": true, "mail": true,
	"administrator": true, "default": true, "password": true, "login": true,
	"null": true, "none": true, "localhost": true, "dev": true, "web": true,
	"app": true, "info": true,
}

// Free-mail providers: an email there keeps its domain (u-xxxx@gmail.com).
var freeMailDomains = map[string]bool{
	"gmail.com": true, "googlemail.com": true, "outlook.com": true, "hotmail.com": true,
	"live.com": true, "msn.com": true, "yahoo.com": true, "ymail.com": true,
	"icloud.com": true, "me.com": true, "mac.com": true, "aol.com": true,
	"proton.me": true, "protonmail.com": true, "pm.me": true, "gmx.com": true,
	"gmx.net": true, "gmx.de": true, "mail.com": true, "yandex.com": true,
	"yandex.ru": true, "zoho.com": true, "sapo.pt": true, "hotmail.pt": true,
	"outlook.pt": true, "fastmail.com": true, "tutanota.com": true, "qq.com": true,
	"163.com": true,
}

// entry is one decrypted mapping held in memory.
type entry struct {
	kind       Kind
	norm       string // normalised form (index HMAC input)
	original   string // stored original (as first enrolled, trimmed)
	alias      string
	companyIDs []int64
	taskIDs    []int64
}

// Store is the in-memory index over the encrypted mapping table. It is safe
// for concurrent use; enrolment is serialised per Store.
type Store struct {
	p         Persistence
	aead      cipher.AEAD
	indexKey  []byte
	deriveKey []byte
	deriver   *Deriver

	// keywordAlias mints org/product/person (and private-key) aliases; attempt
	// > 0 re-derives after a collision. Test seam (ruling R2).
	keywordAlias func(kind Kind, term string, attempt int) string

	enrollMu sync.Mutex // serialises Enroll/IPv4Alias/SeedCIDR

	mu         sync.RWMutex
	byKey      map[string]*entry // kind+"\x00"+norm
	origSens   map[string]*entry // norm of case-sensitive kinds (incl. IPs)
	origFold   map[string]*entry // norm of case-insensitive kinds
	aliasExact map[string]*entry
	aliasFold  map[string]*entry // lower(alias) of case-insensitive kinds
	roots      map[string]string // enrolled real root domain -> alias
	blocks     []ipBlock
	dict       *Automaton
	dictDirty  bool
	modelKnown map[string]bool
}

// OpenStore loads and decrypts every entry. encKey must be 32 bytes
// (AES-256) and hmacKey 32 bytes. A row that does not decrypt, or whose
// original does not match its index HMAC, is an error (wrong keys).
func OpenStore(p Persistence, encKey, hmacKey []byte) (*Store, error) {
	if len(encKey) != 32 {
		return nil, fmt.Errorf("membrane store: encryption key must be 32 bytes, got %d", len(encKey))
	}
	if len(hmacKey) != 32 {
		return nil, fmt.Errorf("membrane store: hmac key must be 32 bytes, got %d", len(hmacKey))
	}
	blk, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	s := &Store{
		p:          p,
		aead:       aead,
		indexKey:   hmacSum(hmacKey, indexKeyLabel),
		deriveKey:  hmacSum(hmacKey, deriveKeyLabel),
		modelKnown: map[string]bool{},
	}
	s.deriver = NewDeriver(s.deriveKey)
	s.keywordAlias = s.defaultKeywordAlias
	if err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

func hmacSum(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

func (s *Store) indexHMAC(kind Kind, norm string) string {
	return hex.EncodeToString(hmacSum(s.indexKey, string(kind)+"\x00"+norm))
}

func (s *Store) encrypt(kind Kind, mac, plain string) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, []byte(plain), []byte(string(kind)+"\x00"+mac)), nil
}

func (s *Store) decrypt(kind, mac string, ct []byte) (string, error) {
	n := s.aead.NonceSize()
	if len(ct) < n {
		return "", errors.New("ciphertext too short")
	}
	pt, err := s.aead.Open(nil, ct[:n], ct[n:], []byte(kind+"\x00"+mac))
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

// reload rebuilds the in-memory index from persistence.
func (s *Store) reload() error {
	rows, err := s.p.ListMembraneEntries()
	if err != nil {
		return fmt.Errorf("membrane store: list entries: %w", err)
	}
	brows, err := s.p.ListMembraneBlocks()
	if err != nil {
		return fmt.Errorf("membrane store: list blocks: %w", err)
	}
	fresh := &Store{}
	fresh.resetMaps()
	for _, r := range rows {
		orig, err := s.decrypt(r.Kind, r.OriginalHMAC, r.OriginalEnc)
		if err != nil {
			return fmt.Errorf("membrane store: decrypt entry %d: %w (wrong ARTEX_MEMBRANE_KEY?)", r.ID, err)
		}
		norm, _, err := normalise(Kind(r.Kind), orig)
		if err != nil {
			return fmt.Errorf("membrane store: entry %d: %w", r.ID, err)
		}
		if !hmac.Equal([]byte(s.indexHMAC(Kind(r.Kind), norm)), []byte(r.OriginalHMAC)) {
			return fmt.Errorf("membrane store: entry %d: index HMAC mismatch (wrong ARTEX_MEMBRANE_HMAC_KEY?)", r.ID)
		}
		fresh.indexEntry(&entry{kind: Kind(r.Kind), norm: norm, original: orig, alias: r.Alias,
			companyIDs: r.CompanyIDs, taskIDs: r.TaskIDs})
	}
	for _, b := range brows {
		blk, err := parseBlock(b)
		if err != nil {
			return err
		}
		fresh.blocks = append(fresh.blocks, blk)
	}
	s.mu.Lock()
	s.byKey, s.origSens, s.origFold = fresh.byKey, fresh.origSens, fresh.origFold
	s.aliasExact, s.aliasFold, s.roots = fresh.aliasExact, fresh.aliasFold, fresh.roots
	s.blocks = fresh.blocks
	s.dict, s.dictDirty = nil, true
	s.mu.Unlock()
	return nil
}

func (s *Store) resetMaps() {
	s.byKey = map[string]*entry{}
	s.origSens = map[string]*entry{}
	s.origFold = map[string]*entry{}
	s.aliasExact = map[string]*entry{}
	s.aliasFold = map[string]*entry{}
	s.roots = map[string]string{}
}

// indexEntry adds e to the maps. Caller holds mu (or owns s exclusively).
func (s *Store) indexEntry(e *entry) {
	s.byKey[string(e.kind)+"\x00"+e.norm] = e
	if foldKind(e.kind) {
		if _, ok := s.origFold[e.norm]; !ok {
			s.origFold[e.norm] = e
		}
		s.aliasFold[strings.ToLower(e.alias)] = e
	} else if _, ok := s.origSens[e.norm]; !ok {
		s.origSens[e.norm] = e
	}
	s.aliasExact[e.alias] = e
	if e.kind == KindDomain && isRootDomain(e.norm) {
		s.roots[e.norm] = e.alias
	}
	s.dictDirty = true
}

// foldKind reports whether originals of kind match case-insensitively.
func foldKind(k Kind) bool {
	switch k {
	case KindDomain, KindEmail, KindOrg, KindProduct, KindPerson:
		return true
	}
	return false
}

func isKeywordKind(k Kind) bool { return k == KindOrg || k == KindProduct || k == KindPerson }

func isRootDomain(d string) bool {
	r, err := publicsuffix.EffectiveTLDPlusOne(d)
	return err == nil && r == d
}

// normDomain lowercases, strips a trailing dot and converts to punycode.
func normDomain(s string) (string, error) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || strings.ContainsAny(s, " \t\r\n/@:") {
		return "", fmt.Errorf("invalid domain %q", s)
	}
	a, err := idna.Punycode.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", s, err)
	}
	return strings.ToLower(a), nil
}

// normalise returns the lookup form (HMAC input) and the stored form.
func normalise(kind Kind, s string) (norm, stored string, err error) {
	switch kind {
	case KindDomain:
		d, err := normDomain(s)
		return d, d, err
	case KindEmail:
		t := strings.TrimSpace(s)
		i := strings.LastIndexByte(t, '@')
		if i <= 0 {
			return "", "", fmt.Errorf("invalid email")
		}
		d, err := normDomain(t[i+1:])
		if err != nil {
			return "", "", err
		}
		e := strings.ToLower(t[:i]) + "@" + d
		return e, e, nil
	case KindOrg, KindProduct, KindPerson:
		t := strings.TrimSpace(s)
		if t == "" {
			return "", "", fmt.Errorf("empty %s", kind)
		}
		return strings.ToLower(t), t, nil
	case KindIPv4, KindIPv6:
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return "", "", err
		}
		c := a.Unmap().String()
		return c, c, nil
	}
	if s == "" {
		return "", "", fmt.Errorf("empty %s", kind)
	}
	return s, s, nil
}

func (s *Store) defaultKeywordAlias(kind Kind, term string, attempt int) string {
	if attempt == 0 {
		return s.deriver.Keyword(kind, term)
	}
	return s.deriver.Keyword(kind, term+"\x00"+strconv.Itoa(attempt))
}

// deriverFor returns the deriver for a re-derivation attempt: attempt 0 is
// the main deriver, later attempts use a domain-separated subkey.
func (s *Store) deriverFor(attempt int) *Deriver {
	if attempt == 0 {
		return s.deriver
	}
	return NewDeriver(hmacSum(s.deriveKey, rehashLabel+"\x00"+strconv.Itoa(attempt)))
}

// Enroll returns the alias for original, minting and persisting it on first
// sight. Repeated or concurrent calls for the same original return the same
// alias. Values that are not aliased (private IPs, values already in the
// alias space) are returned unchanged and not stored.
func (s *Store) Enroll(kind Kind, original string, prov Provenance) (string, error) {
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	return s.enrollLocked(kind, original, prov)
}

func (s *Store) enrollLocked(kind Kind, original string, prov Provenance) (string, error) {
	norm, stored, err := normalise(kind, original)
	if err != nil {
		return "", fmt.Errorf("membrane enroll: %w", err)
	}
	switch kind {
	case KindIPv4, KindIPv6:
		a, _ := netip.ParseAddr(norm)
		if a.Is4() != (kind == KindIPv4) {
			return "", fmt.Errorf("membrane enroll: %q is not %s", norm, kind)
		}
		if !isPublicIP(a) {
			return norm, nil
		}
	case KindDomain:
		if norm == "example" || strings.HasSuffix(norm, ".example") {
			return norm, nil // already alias space (RFC 2606)
		}
	}

	key := string(kind) + "\x00" + norm
	s.mu.RLock()
	e := s.byKey[key]
	s.mu.RUnlock()
	if e != nil {
		if err := s.mergeProvenance(e, prov); err != nil {
			return "", err
		}
		return e.alias, nil
	}

	mac := s.indexHMAC(kind, norm)
	reloaded := false
	for attempt := 0; attempt < maxMintAttempt; attempt++ {
		alias, err := s.mint(kind, norm, stored, attempt, prov)
		if err != nil {
			return "", fmt.Errorf("membrane enroll %s: %w", kind, err)
		}
		s.mu.RLock()
		taken := s.aliasExact[alias] != nil || s.aliasFold[strings.ToLower(alias)] != nil
		s.mu.RUnlock()
		if taken {
			continue
		}
		enc, err := s.encrypt(kind, mac, stored)
		if err != nil {
			return "", err
		}
		row, err := s.p.InsertMembraneEntry(&db.MembraneEntry{
			Kind: string(kind), OriginalHMAC: mac, OriginalEnc: enc, Alias: alias,
			Source: sourceOf(prov), CompanyIDs: prov.CompanyIDs, TaskIDs: prov.TaskIDs,
		})
		if err != nil {
			// Another process may have taken the alias or the row: refresh
			// once and retry from the same attempt.
			if reloaded {
				return "", fmt.Errorf("membrane enroll %s: %w", kind, err)
			}
			if rerr := s.reload(); rerr != nil {
				return "", rerr
			}
			reloaded = true
			s.mu.RLock()
			e := s.byKey[key]
			s.mu.RUnlock()
			if e != nil {
				return e.alias, nil
			}
			attempt--
			continue
		}
		// On conflict the row (and alias) of an earlier enrolment wins.
		ne := &entry{kind: kind, norm: norm, original: stored, alias: row.Alias,
			companyIDs: row.CompanyIDs, taskIDs: row.TaskIDs}
		s.mu.Lock()
		s.indexEntry(ne)
		s.mu.Unlock()
		return row.Alias, nil
	}
	return "", fmt.Errorf("membrane enroll %s: no free alias after %d attempts", kind, maxMintAttempt)
}

func sourceOf(p Provenance) string {
	if p.Source == "" {
		return "auto"
	}
	return p.Source
}

// mergeProvenance persists provenance ids that e does not have yet.
func (s *Store) mergeProvenance(e *entry, prov Provenance) error {
	s.mu.RLock()
	covered := containsAll(e.companyIDs, prov.CompanyIDs) && containsAll(e.taskIDs, prov.TaskIDs)
	s.mu.RUnlock()
	if covered {
		return nil
	}
	mac := s.indexHMAC(e.kind, e.norm)
	enc, err := s.encrypt(e.kind, mac, e.original)
	if err != nil {
		return err
	}
	row, err := s.p.InsertMembraneEntry(&db.MembraneEntry{
		Kind: string(e.kind), OriginalHMAC: mac, OriginalEnc: enc, Alias: e.alias,
		Source: sourceOf(prov), CompanyIDs: prov.CompanyIDs, TaskIDs: prov.TaskIDs,
	})
	if err != nil {
		return fmt.Errorf("membrane enroll %s: merge provenance: %w", e.kind, err)
	}
	s.mu.Lock()
	e.companyIDs, e.taskIDs = row.CompanyIDs, row.TaskIDs
	s.mu.Unlock()
	return nil
}

func containsAll(have, want []int64) bool {
	for _, w := range want {
		if !slices.Contains(have, w) {
			return false
		}
	}
	return true
}

// mint derives the candidate alias for attempt. Caller holds enrollMu.
func (s *Store) mint(kind Kind, norm, stored string, attempt int, prov Provenance) (string, error) {
	switch kind {
	case KindDomain:
		return s.mintDomain(norm, attempt, prov)
	case KindEmail:
		return s.mintEmail(norm, attempt, prov)
	case KindOrg, KindProduct, KindPerson:
		return s.keywordAlias(kind, norm, attempt), nil
	case KindPrivateKey:
		k := s.keywordAlias(kind, norm, attempt)
		return "[PRIVATE_KEY_" + k[strings.LastIndexByte(k, '-')+1:] + "]", nil
	case KindIPv4:
		if attempt > 0 {
			return "", fmt.Errorf("ipv4 alias of %s already taken", norm)
		}
		a, err := s.mapIPv4(netip.MustParseAddr(norm))
		return a.String(), err
	case KindIPv6:
		return s.deriverFor(attempt).IPv6(netip.MustParseAddr(norm)).String(), nil
	}
	return s.deriverFor(attempt).FormatPreserving(kind, stored), nil
}

func (s *Store) mintDomain(norm string, attempt int, prov Provenance) (string, error) {
	root, err := publicsuffix.EffectiveTLDPlusOne(norm)
	if err != nil {
		return "", err
	}
	if root == norm {
		if attempt == 0 {
			return s.deriver.RootDomain(norm), nil
		}
		return s.deriver.RootDomain(norm + "\x00" + strconv.Itoa(attempt)), nil
	}
	if attempt > 0 {
		return "", fmt.Errorf("subdomain alias collision for a host under %s", root)
	}
	rootAlias, err := s.enrollLocked(KindDomain, root, prov)
	if err != nil {
		return "", err
	}
	labels := strings.Split(strings.TrimSuffix(norm, "."+root), ".")
	dict := s.Dictionary()
	for i, l := range labels {
		labels[i] = replaceKeywords(dict, l)
	}
	return strings.Join(labels, ".") + "." + rootAlias, nil
}

// replaceKeywords swaps enrolled org/product/person keywords inside a DNS
// label for their lowercase alias.
func replaceKeywords(dict *Automaton, label string) string {
	ms := dict.findAll(label, isKeywordKind)
	if len(ms) == 0 {
		return label
	}
	var b strings.Builder
	last := 0
	for _, m := range ms {
		b.WriteString(label[last:m.Start])
		b.WriteString(strings.ToLower(m.Alias))
		last = m.End
	}
	b.WriteString(label[last:])
	return b.String()
}

func (s *Store) mintEmail(norm string, attempt int, prov Provenance) (string, error) {
	i := strings.LastIndexByte(norm, '@')
	local, dom := norm[:i], norm[i+1:]
	if attempt > 0 {
		local += "\x00" + strconv.Itoa(attempt)
	}
	la := s.deriver.EmailLocal(local)
	if freeMailDomains[dom] {
		return "u-" + strings.TrimPrefix(la, "user-") + "@" + dom, nil
	}
	da, err := s.enrollLocked(KindDomain, dom, prov)
	if err != nil {
		return "", err
	}
	return la + "@" + da, nil
}

// AliasFor returns the alias of an enrolled original, kind-agnostic.
// Case-insensitive kinds (domains, emails, keywords) match in any case.
func (s *Store) AliasFor(original string) (alias string, kind Kind, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e := s.origSens[original]; e != nil {
		return e.alias, e.kind, true
	}
	t := strings.TrimSpace(original)
	if e := s.origFold[strings.ToLower(t)]; e != nil {
		return e.alias, e.kind, true
	}
	if d, err := normDomain(t); err == nil {
		if e := s.origFold[d]; e != nil {
			return e.alias, e.kind, true
		}
	}
	if a, err := netip.ParseAddr(t); err == nil {
		if e := s.origSens[a.Unmap().String()]; e != nil {
			return e.alias, e.kind, true
		}
	}
	return "", "", false
}

// OriginalFor returns the original of an exactly known alias, kind-agnostic.
// Aliases of case-insensitive kinds match in any case. Derivation rules
// (subdomains, IPs inside blocks) are not applied here; see IPv4Real.
func (s *Store) OriginalFor(alias string) (original string, kind Kind, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e := s.aliasExact[alias]; e != nil {
		return e.original, e.kind, true
	}
	t := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(alias)), ".")
	if e := s.aliasFold[t]; e != nil {
		return e.original, e.kind, true
	}
	return "", "", false
}

// Roots returns the enrolled real root domains (eTLD+1), sorted.
func (s *Store) Roots() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.roots))
	for r := range s.roots {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// MarkModelKnown records a domain first introduced by the model (in memory
// only for now).
func (s *Store) MarkModelKnown(domain string) {
	d, err := normDomain(domain)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.modelKnown[d] = true
	s.mu.Unlock()
}

// IsModelKnown reports whether domain was marked model-known. A domain at or
// under an enrolled root is never model-known.
func (s *Store) IsModelKnown(domain string) bool {
	d, err := normDomain(domain)
	if err != nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r, err := publicsuffix.EffectiveTLDPlusOne(d); err == nil {
		if _, protected := s.roots[r]; protected {
			return false
		}
	}
	return s.modelKnown[d]
}

// Dictionary returns an immutable automaton snapshot over the enrolled
// originals, rebuilt lazily after enrolment. IP addresses are left to the
// structural detectors; originals shorter than 3 bytes or on the ambiguous
// word stoplist are left out (they remain available to AliasFor).
func (s *Store) Dictionary() *Automaton {
	s.mu.RLock()
	if !s.dictDirty {
		d := s.dict
		s.mu.RUnlock()
		return d
	}
	s.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dictDirty {
		s.dict = buildAutomaton(s.patternsLocked())
		s.dictDirty = false
	}
	return s.dict
}

func (s *Store) patternsLocked() []acPattern {
	keys := make([]string, 0, len(s.byKey))
	for k := range s.byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var pats []acPattern
	add := func(e *entry, text string) {
		if len(text) < minLiteralLen || literalStoplist[strings.ToLower(text)] {
			return
		}
		pats = append(pats, acPattern{text: text, original: e.original, kind: e.kind,
			alias: e.alias, caseSensitive: !foldKind(e.kind)})
	}
	for _, k := range keys {
		e := s.byKey[k]
		if e.kind == KindIPv4 || e.kind == KindIPv6 {
			continue
		}
		add(e, e.original)
		if e.kind == KindDomain {
			if u, err := idna.Punycode.ToUnicode(e.norm); err == nil && u != e.norm {
				add(e, u)
			}
		}
	}
	return pats
}
