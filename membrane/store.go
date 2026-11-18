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
	"sync/atomic"
	"unicode"
	"unicode/utf8"

	"github.com/Autumn-27/artex/db"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Persistence is the subset of *db.DB the Store needs.
type Persistence interface {
	InsertMembraneEntry(e *db.MembraneEntry) (db.MembraneEntry, error)
	ListMembraneEntries() ([]db.MembraneEntry, error)
	UpdateMembraneEntryAlias(id int64, newAlias string) error
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

// shortKeywordMax is the longest keyword (in runes) that only matches at
// token boundaries; longer keywords also match inside compounds (ruling R10).
const shortKeywordMax = 4

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
	id         int64
	kind       Kind
	norm       string // normalised form (index HMAC input)
	original   string // stored original (as first enrolled, trimmed)
	alias      string
	retired    []string // earlier aliases, valid for reverse lookup only
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
	rdict      *Automaton // reverse (alias -> original) automaton
	rdictGen   uint64     // aliasGen rdict was built at
	modelKnown map[string]bool
	// phones by international core digits (no +/00 prefix) of the original
	// and of the alias, for the digits-only / + / 00 variants.
	phoneOrig  map[string]*entry
	phoneAlias map[string]*entry

	// gen counts every change that can alter a transform's output
	// (enrolment, re-mint, block allocation, model-known marks, reload).
	gen atomic.Uint64
	// aliasGen counts changes to the alias set only (rdict rebuilds).
	aliasGen atomic.Uint64
}

// generation returns the store's change counter.
func (s *Store) generation() uint64 { return s.gen.Load() }

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
	// Heal any re-mint that failed part-way earlier (ruling R9). Failing here
	// fails closed: a store that would emit a keyword in clear is not opened.
	if err := s.remintAllKeywords(); err != nil {
		return nil, fmt.Errorf("membrane store: re-mint sweep: %w", err)
	}
	return s, nil
}

// remintAllKeywords runs remintForKeyword for every enrolled keyword.
func (s *Store) remintAllKeywords() error {
	s.mu.RLock()
	seen := map[string]bool{}
	var kws []string
	for _, e := range s.byKey {
		if isKeywordKind(e.kind) && !seen[e.norm] {
			seen[e.norm] = true
			kws = append(kws, e.norm)
		}
	}
	s.mu.RUnlock()
	sort.Strings(kws)
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	for _, k := range kws {
		if err := s.remintForKeyword(k); err != nil {
			return err
		}
	}
	return nil
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
			return fmt.Errorf("membrane store: entry %d: stored %s original does not normalise", r.ID, r.Kind)
		}
		if !hmac.Equal([]byte(s.indexHMAC(Kind(r.Kind), norm)), []byte(r.OriginalHMAC)) {
			return fmt.Errorf("membrane store: entry %d: index HMAC mismatch (wrong ARTEX_MEMBRANE_HMAC_KEY?)", r.ID)
		}
		fresh.indexEntry(&entry{id: r.ID, kind: Kind(r.Kind), norm: norm, original: orig, alias: r.Alias,
			retired: r.RetiredAliases, companyIDs: r.CompanyIDs, taskIDs: r.TaskIDs})
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
	s.phoneOrig, s.phoneAlias = fresh.phoneOrig, fresh.phoneAlias
	s.blocks = fresh.blocks
	s.dict, s.dictDirty = nil, true
	s.gen.Add(1)
	s.aliasGen.Add(1)
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
	s.phoneOrig = map[string]*entry{}
	s.phoneAlias = map[string]*entry{}
}

// indexEntry adds e to the maps. Caller holds mu (or owns s exclusively).
func (s *Store) indexEntry(e *entry) {
	s.byKey[string(e.kind)+"\x00"+e.norm] = e
	if foldKind(e.kind) {
		if _, ok := s.origFold[e.norm]; !ok {
			s.origFold[e.norm] = e
		}
	} else if _, ok := s.origSens[e.norm]; !ok {
		s.origSens[e.norm] = e
	}
	for _, a := range e.retired {
		s.indexAlias(e, a)
	}
	s.indexAlias(e, e.alias)
	if e.kind == KindDomain && isRootDomain(e.norm) {
		s.roots[e.norm] = e.alias
	}
	if e.kind == KindPhone {
		if oc, ac, ok := phoneCores(e); ok {
			s.phoneOrig[oc] = e
			s.phoneAlias[ac] = e
		}
	}
	s.dictDirty = true
	s.gen.Add(1)
	s.aliasGen.Add(1)
}

// Phone variants. An international phone (+351 912 345 678, 00351912345678)
// is also written digits-only (351912345678), with + or with 00. Each such
// variant of the original maps to the same variant of the alias (the
// format-preserving alias keeps the digit positions), and back: the form
// that appeared is the form produced, in both directions.

// phoneCore returns the international core digits of v when v is a phone
// written with a + or 00 prefix, or digits only, with separators only; and
// the variant form (0 digits only, 1 "+", 2 "00").
func phoneCore(v string) (core string, form int, ok bool) {
	t := strings.TrimSpace(v)
	for _, r := range t {
		if !(r >= '0' && r <= '9') && !strings.ContainsRune("+ -.()", r) {
			return "", 0, false
		}
	}
	d := onlyDigits(t)
	switch {
	case strings.HasPrefix(t, "+"):
		core, form = d, 1
	case strings.HasPrefix(t, "00"):
		core, form = d[2:], 2
	default:
		core, form = d, 0
	}
	return core, form, len(core) >= 9
}

// phoneCores returns the core digits of a phone entry's original and alias.
// Only originals written with an international prefix have variants.
func phoneCores(e *entry) (orig, alias string, ok bool) {
	oc, form, ok := phoneCore(e.original)
	if !ok || form == 0 {
		return "", "", false
	}
	ad := onlyDigits(e.alias)
	if form == 2 && len(ad) >= 2 {
		ad = ad[2:]
	}
	return oc, ad, len(ad) == len(oc)
}

// phoneForm writes core in variant form f.
func phoneForm(core string, f int) string {
	switch f {
	case 1:
		return "+" + core
	case 2:
		return "00" + core
	}
	return core
}

// phoneVariants lists the variant forms of a phone entry as pairs
// {original form, alias form}; the entry's own spelling is left out.
func phoneVariants(e *entry) [][2]string {
	oc, ac, ok := phoneCores(e)
	if !ok {
		return nil
	}
	var out [][2]string
	for f := 0; f < 3; f++ {
		if o := phoneForm(oc, f); o != e.original {
			out = append(out, [2]string{o, phoneForm(ac, f)})
		}
	}
	return out
}

// indexAlias makes a (current or retired) resolve to e. Caller holds mu.
func (s *Store) indexAlias(e *entry, a string) {
	s.aliasExact[a] = e
	if foldKind(e.kind) {
		s.aliasFold[strings.ToLower(a)] = e
	}
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
		return "", errors.New("invalid domain")
	}
	a, err := idna.Punycode.ToASCII(s)
	if err != nil {
		return "", errors.New("invalid domain (not IDNA-encodable)")
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
			return "", "", fmt.Errorf("invalid %s address", kind) // library error embeds the input
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
	return s.enrollLocked(kind, original, prov, false)
}

// enrollLookalike enrols a real value that is shaped like an alias (a
// 240/4 or 2001:db8::/32 address, a host under .example) and that the store
// did not mint (ruling R11). Unlike Enroll it does not return such values
// unchanged. A value that is itself a minted alias is refused (fail closed):
// enrolling it would put an alias into the dictionary of originals.
func (s *Store) enrollLookalike(kind Kind, original string, prov Provenance) (string, error) {
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	return s.enrollLocked(kind, original, prov, true)
}

func (s *Store) enrollLocked(kind Kind, original string, prov Provenance, look bool) (string, error) {
	norm, stored, err := normalise(kind, original)
	if err != nil {
		return "", fmt.Errorf("membrane enroll: %w", err)
	}
	switch kind {
	case KindIPv4, KindIPv6:
		a, _ := netip.ParseAddr(norm)
		if a.Is4() != (kind == KindIPv4) {
			return "", fmt.Errorf("membrane enroll: address is not %s", kind)
		}
		if !isPublicIP(a) && !(look && inAliasSpace(a)) {
			return norm, nil
		}
	case KindDomain:
		if !look && (norm == "example" || strings.HasSuffix(norm, ".example")) {
			return norm, nil // already alias space (RFC 2606)
		}
	}
	if look && s.aliasTaken(norm) {
		return "", fmt.Errorf("membrane enroll %s: refusing to enrol a minted alias as an original", kind)
	}

	key := string(kind) + "\x00" + norm
	s.mu.RLock()
	e := s.byKey[key]
	s.mu.RUnlock()
	if e != nil {
		if err := s.mergeProvenance(e, prov); err != nil {
			return "", err
		}
		if remintKind(kind) {
			// Idempotent: heals a re-mint that failed on an earlier call.
			if err := s.remintForKeyword(norm); err != nil {
				return "", err
			}
		}
		return e.alias, nil
	}

	mac := s.indexHMAC(kind, norm)
	reloaded := false
	for attempt := 0; attempt < maxMintAttempt; attempt++ {
		alias, err := s.mint(kind, norm, stored, attempt, prov, look)
		if err != nil {
			return "", fmt.Errorf("membrane enroll %s: %w", kind, err)
		}
		if s.aliasTaken(alias) || (kind != KindIPv4 && kind != KindIPv6 && s.isOriginal(alias)) {
			continue // an alias equal to an original would trip the leak check
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
		ne := &entry{id: row.ID, kind: kind, norm: norm, original: stored, alias: row.Alias,
			retired: row.RetiredAliases, companyIDs: row.CompanyIDs, taskIDs: row.TaskIDs}
		s.mu.Lock()
		s.indexEntry(ne)
		s.mu.Unlock()
		if remintKind(kind) {
			if err := s.remintForKeyword(norm); err != nil {
				return "", err
			}
		}
		return row.Alias, nil
	}
	return "", fmt.Errorf("membrane enroll %s: no free alias after %d attempts", kind, maxMintAttempt)
}

// aliasTaken reports whether alias (current or retired, any case) is in use.
func (s *Store) aliasTaken(alias string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.aliasExact[alias] != nil || s.aliasFold[strings.ToLower(alias)] != nil
}

// isOriginal reports whether v (any case) is an enrolled original.
func (s *Store) isOriginal(v string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.origSens[v] != nil || s.origFold[strings.ToLower(v)] != nil
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
func (s *Store) mint(kind Kind, norm, stored string, attempt int, prov Provenance, look bool) (string, error) {
	switch kind {
	case KindDomain:
		return s.mintDomain(norm, attempt, prov, look)
	case KindEmail:
		return s.mintEmail(norm, attempt, prov, look)
	case KindOrg, KindProduct, KindPerson:
		return s.keywordAlias(kind, norm, attempt), nil
	case KindPrivateKey:
		k := s.keywordAlias(kind, norm, attempt)
		return "[PRIVATE_KEY_" + k[strings.LastIndexByte(k, '-')+1:] + "]", nil
	case KindIPv4:
		if attempt > 0 {
			return "", errors.New("ipv4 alias already taken")
		}
		a, err := s.mapIPv4(netip.MustParseAddr(norm))
		return a.String(), err
	case KindIPv6:
		return s.deriverFor(attempt).IPv6(netip.MustParseAddr(norm)).String(), nil
	}
	return formatPreservingAlias(s.deriverFor(attempt), kind, stored), nil
}

// formatPreservingAlias is FormatPreserving, except that a value with no
// letter or digit to substitute ("!!!") would come back unchanged; it then
// gets same-length lowercase letters instead, so no alias equals its
// original.
func formatPreservingAlias(d *Deriver, kind Kind, original string) string {
	if a := d.FormatPreserving(kind, original); a != original {
		return a
	}
	mac := d.mac("format-preserving-fallback", string(kind), original)
	n := utf8.RuneCountInString(original)
	out := make([]byte, n)
	for i := range out {
		out[i] = 'a' + mac[i%len(mac)]%26
	}
	return string(out)
}

// subdomainAlias renders the alias of a non-root host from its real labels,
// the current dictionary and the root alias.
func (s *Store) subdomainAlias(norm, root, rootAlias string) string {
	return replaceLiterals(s.Dictionary(), strings.TrimSuffix(norm, "."+root)) + "." + rootAlias
}

// remintKind reports whether enrolling an original of kind k may require
// re-minting host aliases whose preserved labels contain it: every literal
// replaceLiterals substitutes inside labels. Domains and emails are left out
// (a host written inside another host's labels is rare, and a scan per new
// host would make enrolment quadratic).
func remintKind(k Kind) bool {
	switch k {
	case KindIPv4, KindIPv6, KindDomain, KindEmail:
		return false
	}
	return true
}

// remintForKeyword gives a new alias to every domain (and email on such a
// domain) whose alias still carries keyword in clear (any case), because it
// was enrolled before it (ruling R9). keyword is an org/product/person
// keyword or, since Task 5, any literal replaceLiterals substitutes. The old
// alias is retired: it keeps resolving in OriginalFor but is never emitted
// again. Caller holds enrollMu.
func (s *Store) remintForKeyword(keyword string) error {
	keyword = strings.ToLower(keyword)
	if len(keyword) < minLiteralLen || literalStoplist[keyword] {
		return nil // not in the automaton, so it cannot be substituted
	}
	s.mu.RLock()
	var hosts, mails []*entry
	for _, e := range s.byKey {
		switch e.kind {
		case KindDomain:
			if !s.isRootLocked(e.norm) && strings.Contains(strings.ToLower(e.alias), keyword) {
				hosts = append(hosts, e)
			}
		case KindEmail:
			if strings.Contains(strings.ToLower(e.alias), keyword) {
				mails = append(mails, e)
			}
		}
	}
	s.mu.RUnlock()
	sort.Slice(hosts, func(i, j int) bool { return hosts[i].id < hosts[j].id })
	sort.Slice(mails, func(i, j int) bool { return mails[i].id < mails[j].id })

	for _, e := range hosts {
		root, err := publicsuffix.EffectiveTLDPlusOne(e.norm)
		if err != nil {
			continue
		}
		s.mu.RLock()
		rootAlias, ok := s.roots[root]
		s.mu.RUnlock()
		if !ok {
			continue
		}
		if err := s.retireAlias(e, s.subdomainAlias(e.norm, root, rootAlias)); err != nil {
			return err
		}
	}
	for _, e := range mails {
		i := strings.LastIndexByte(e.alias, '@')
		j := strings.LastIndexByte(e.norm, '@')
		if i < 0 || j < 0 {
			continue
		}
		da, _, ok := s.AliasFor(e.norm[j+1:])
		if !ok {
			continue
		}
		if err := s.retireAlias(e, e.alias[:i+1]+da); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) isRootLocked(norm string) bool {
	_, ok := s.roots[norm]
	return ok
}

// retireAlias moves e to newAlias, persisting it and keeping the old alias
// for reverse lookup. Caller holds enrollMu.
func (s *Store) retireAlias(e *entry, newAlias string) error {
	if newAlias == e.alias {
		return nil
	}
	if s.aliasTaken(newAlias) {
		return fmt.Errorf("membrane re-mint %s entry %d: alias collision", e.kind, e.id)
	}
	if err := s.p.UpdateMembraneEntryAlias(e.id, newAlias); err != nil {
		return fmt.Errorf("membrane re-mint %s entry %d: %w", e.kind, e.id, err)
	}
	s.mu.Lock()
	e.retired = append(append([]string(nil), e.retired...), e.alias)
	e.alias = newAlias
	s.indexAlias(e, newAlias)
	if e.kind == KindDomain && s.isRootLocked(e.norm) {
		s.roots[e.norm] = newAlias
	}
	s.dictDirty = true
	s.gen.Add(1)
	s.aliasGen.Add(1)
	s.mu.Unlock()
	return nil
}

func (s *Store) mintDomain(norm string, attempt int, prov Provenance, look bool) (string, error) {
	root, err := publicsuffix.EffectiveTLDPlusOne(norm)
	if err != nil {
		return "", errors.New("domain has no registrable root") // library error embeds the input
	}
	if root == norm {
		if attempt == 0 {
			return s.deriver.RootDomain(norm), nil
		}
		return s.deriver.RootDomain(norm + "\x00" + strconv.Itoa(attempt)), nil
	}
	if attempt > 0 {
		return "", errors.New("subdomain alias collision")
	}
	rootAlias, err := s.enrollLocked(KindDomain, root, prov, look)
	if err != nil {
		return "", err
	}
	return s.subdomainAlias(norm, root, rootAlias), nil
}

// replaceLiterals swaps every enrolled original written inside the
// preserved labels of a host (prefix: the labels before the root) for its
// alias, so no label carries an original in clear: org/product/person
// keywords become their lowercase DNS form (acmebank-vpn -> org-7f2c-vpn),
// domains their alias (corpx.io.internal -> 57ddff.example.internal), and
// usernames, secrets and the like their format-preserving alias
// (jsilva-pc -> tjwzxx-pc). Keywords of 3-4 runes are replaced only as
// whole tokens (ruling R10): "billing" keeps its "ing".
func replaceLiterals(dict *Automaton, prefix string) string {
	ms := dict.FindAll(prefix)
	if len(ms) == 0 {
		return prefix
	}
	var b strings.Builder
	last := 0
	for _, m := range ms {
		b.WriteString(prefix[last:m.Start])
		if isKeywordKind(m.Kind) {
			b.WriteString(strings.ToLower(m.Alias))
		} else {
			b.WriteString(m.Alias)
		}
		last = m.End
	}
	b.WriteString(prefix[last:])
	return b.String()
}

func (s *Store) mintEmail(norm string, attempt int, prov Provenance, look bool) (string, error) {
	i := strings.LastIndexByte(norm, '@')
	local, dom := norm[:i], norm[i+1:]
	if attempt > 0 {
		local += "\x00" + strconv.Itoa(attempt)
	}
	la := s.deriver.EmailLocal(local)
	if freeMailDomains[dom] {
		return "u-" + strings.TrimPrefix(la, "user-") + "@" + dom, nil
	}
	da, err := s.enrollLocked(KindDomain, dom, prov, look)
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
	if e := s.entryForLocked(original); e != nil {
		if core, f, ok := phoneCore(original); ok && e.kind == KindPhone && original != e.original && s.phoneOrig[core] == e {
			_, ac, _ := phoneCores(e)
			return phoneForm(ac, f), KindPhone, true // the variant written
		}
		return e.alias, e.kind, true
	}
	return "", "", false
}

// entryForLocked finds the entry of an enrolled original, kind-agnostic.
// Caller holds mu.
func (s *Store) entryForLocked(original string) *entry {
	if e := s.origSens[original]; e != nil {
		return e
	}
	t := strings.TrimSpace(original)
	if e := s.origFold[strings.ToLower(t)]; e != nil {
		return e
	}
	if d, err := normDomain(t); err == nil {
		if e := s.origFold[d]; e != nil {
			return e
		}
	}
	if a, err := netip.ParseAddr(t); err == nil {
		if e := s.origSens[a.Unmap().String()]; e != nil {
			return e
		}
	}
	if core, _, ok := phoneCore(t); ok {
		if e := s.phoneOrig[core]; e != nil {
			return e
		}
	}
	return nil
}

// noteUse records that an enrolled original was seen under prov: company and
// task ids it does not carry yet are merged and persisted, so a purge of one
// company never removes a value another company still relies on. The check
// is in memory; only a missing id costs a write. Unknown originals and an
// empty prov are a no-op.
func (s *Store) noteUse(original string, prov Provenance) error {
	if len(prov.CompanyIDs) == 0 && len(prov.TaskIDs) == 0 {
		return nil
	}
	s.mu.RLock()
	e := s.entryForLocked(original)
	covered := e == nil || (containsAll(e.companyIDs, prov.CompanyIDs) && containsAll(e.taskIDs, prov.TaskIDs))
	s.mu.RUnlock()
	if covered {
		return nil
	}
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	return s.mergeProvenance(e, prov)
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
	if core, f, ok := phoneCore(alias); ok {
		if e := s.phoneAlias[core]; e != nil {
			oc, _, _ := phoneCores(e)
			return phoneForm(oc, f), KindPhone, true
		}
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
	if !s.modelKnown[d] {
		s.modelKnown[d] = true
		s.gen.Add(1)
	}
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
// word stoplist are left out (they remain available to AliasFor). Keywords of
// 3-4 runes match only at token boundaries (ruling R10).
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

// patternBound picks the neighbour rule for a dictionary pattern: short
// keywords match as whole tokens (ruling R10), domains and emails only at
// host-label boundaries so they never match inside another host.
func patternBound(k Kind, text string) boundMode {
	switch {
	case isKeywordKind(k) && utf8.RuneCountInString(text) <= shortKeywordMax:
		return boundToken
	case k == KindDomain:
		return boundHost
	case k == KindEmail:
		return boundEmail
	case isCredentialKind(k) && utf8.RuneCountInString(text) < shortCredentialMax:
		return classBound(text)
	case k == KindPhone:
		return boundDigits
	}
	return boundNone
}

// shortCredentialMax: usernames, passwords and tokens shorter than this
// (in runes) that consist of one character class only must not touch more
// of that class, forward, in the leak check and in reverse: a short value
// or its alias occurs by chance inside other words and numbers (bob in
// bobby, 1234 in 12345). Against the other class they still match (-p1234,
// bob123). Mixed-class short values (abc123x) match anywhere: they do not
// occur by chance. Format-preserving aliases keep the classes, so both
// directions use the same rule.
const shortCredentialMax = 8

// classBound picks boundDigits for an all-digit value, boundLetters for an
// all-letter one, and boundNone otherwise.
func classBound(text string) boundMode {
	digits, letters := true, true
	for _, r := range text {
		digits = digits && unicode.IsDigit(r)
		letters = letters && unicode.IsLetter(r)
	}
	switch {
	case digits:
		return boundDigits
	case letters:
		return boundLetters
	}
	return boundNone
}

func isCredentialKind(k Kind) bool {
	return k == KindUsername || k == KindPassword || k == KindToken
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
			alias: e.alias, caseSensitive: !foldKind(e.kind), bound: patternBound(e.kind, text)})
	}
	for _, k := range keys {
		e := s.byKey[k]
		if e.kind == KindIPv4 || e.kind == KindIPv6 {
			continue
		}
		add(e, e.original)
		for _, v := range phoneVariants(e) {
			pats = append(pats, acPattern{text: v[0], original: v[0], kind: e.kind, alias: v[1],
				caseSensitive: true, bound: boundDigits})
		}
		if e.kind == KindDomain {
			if u, err := idna.Punycode.ToUnicode(e.norm); err == nil && u != e.norm {
				add(e, u)
			}
		}
	}
	return pats
}

// ReverseDictionary returns an immutable automaton over every alias
// (current and retired) that maps back to its original, for ToReal. Like
// Dictionary it leaves out IP aliases (resolved by address, not literal) and
// aliases shorter than 3 bytes. Domain and email aliases match at host
// boundaries, keyword aliases as whole tokens, everything else anywhere
// (mirroring how the forward dictionary placed them).
func (s *Store) ReverseDictionary() *Automaton {
	g := s.aliasGen.Load()
	s.mu.RLock()
	if s.rdict != nil && s.rdictGen == g {
		d := s.rdict
		s.mu.RUnlock()
		return d
	}
	s.mu.RUnlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	g = s.aliasGen.Load()
	if s.rdict == nil || s.rdictGen != g {
		s.rdict, s.rdictGen = buildAutomaton(s.reversePatternsLocked()), g
	}
	return s.rdict
}

func (s *Store) reversePatternsLocked() []acPattern {
	keys := make([]string, 0, len(s.byKey))
	for k := range s.byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var pats []acPattern
	for _, k := range keys {
		e := s.byKey[k]
		if e.kind == KindIPv4 || e.kind == KindIPv6 {
			continue
		}
		for _, a := range append(append([]string(nil), e.retired...), e.alias) {
			if len(a) < minLiteralLen {
				continue
			}
			bound := patternBound(e.kind, a) // aliases keep the original's length
			if isKeywordKind(e.kind) {
				bound = boundToken
			}
			pats = append(pats, acPattern{text: a, original: e.original, kind: e.kind, alias: a,
				caseSensitive: !foldKind(e.kind), bound: bound})
		}
		for _, v := range phoneVariants(e) {
			pats = append(pats, acPattern{text: v[1], original: v[0], kind: e.kind, alias: v[1],
				caseSensitive: true, bound: boundDigits})
		}
	}
	return pats
}

// provenanceOf returns the company and task ids recorded for an enrolled
// original, with Source "auto": the provenance a value derived from it in
// ToReal is enrolled with (ruling R4). Unknown originals give Source "auto"
// and no ids.
func (s *Store) provenanceOf(kind Kind, original string) Provenance {
	p := Provenance{Source: "auto"}
	norm, _, err := normalise(kind, original)
	if err != nil {
		return p
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if e := s.byKey[string(kind)+"\x00"+norm]; e != nil {
		p.CompanyIDs = slices.Clone(e.companyIDs)
		p.TaskIDs = slices.Clone(e.taskIDs)
	}
	return p
}
