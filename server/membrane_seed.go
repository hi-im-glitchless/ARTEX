package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/Autumn-27/artex/membrane"
)

// Seeding the membrane dictionary (spec §7.1): before a task's first LLM
// request, and again at most every 30s while it runs (membrane.Syncer), the
// client values the database already knows are enrolled, so they are aliased
// even where no structural detector would find them:
//   - linked companies: name and its brand variants, company_scope rows
//     (domain, ip, cidr, keyword, icp) and the hosts and IPs of the
//     company's assets;
//   - the task: task_scope rows, task_credentials (domain, username,
//     password), the target host of the description/goal, the hosts and
//     IPs of its own assets, and the structural detections in its
//     description and goal (engine.ToModel, output discarded).
//
// Hosts are classified by their registrable root (classifiedHost): only
// declared roots and roots whose label carries a client keyword become
// client roots (Store.EnrollRoot, plus the root's brand variant); a
// third-party root is never enrolled, only the tenant label of its host.
//
// Company-level values carry provenance {company}; task-level values carry
// {task companies, task}. Source is always "seed". Errors name the step, never
// a value (database errors on these reads carry no row data).

// seedAssetBatch is the page size of the asset scan.
const seedAssetBatch = 1000

// SyncTask implements membrane.Syncer: it seeds the task's values and
// returns its company ids. A non-numeric or unknown task syncs nothing.
func (s *Server) SyncTask(ctx context.Context, taskID string) ([]int64, error) {
	id, err := strconv.ParseInt(taskID, 10, 64)
	if err != nil || id <= 0 {
		return nil, nil
	}
	return s.membraneSyncTaskID(ctx, id)
}

// SyncEpoch implements membrane.SyncEpocher.
func (s *Server) SyncEpoch() uint64 { return s.mem.seedEpoch.Load() }

// SyncGlobal implements membrane.GlobalSyncer: before a request without a
// task id (chat, custom agents) it seeds every company, so a company
// declared after startup is aliased in conversations too (spec §7.1).
func (s *Server) SyncGlobal(ctx context.Context) error {
	sd := s.seeder()
	if sd == nil {
		return nil
	}
	companies, err := s.m.pg.Companies().ListCompanies()
	if err != nil {
		return fmt.Errorf("membrane seed: list companies: %w", err)
	}
	for _, c := range companies {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := sd.company(c.ID); err != nil {
			return fmt.Errorf("membrane seed: company %d: %w", c.ID, err)
		}
	}
	return nil
}

// membraneSeedChanged is called after a seed source changed (spec §7.1:
// seeding happens whenever scope, credentials or companies change): it
// expires every throttled sync, then seeds the changed companies and task
// synchronously so the next request already sees them. The error (step
// names and ids only) is logged and returned for the response; requests
// still fail closed on their own sync.
func (s *Server) membraneSeedChanged(ctx context.Context, companyIDs []int64, taskID int64) error {
	s.mem.seedEpoch.Add(1)
	sd := s.seeder()
	if sd == nil {
		return nil
	}
	var errs []error
	for _, cid := range companyIDs {
		if cid <= 0 {
			continue
		}
		if err := sd.company(cid); err != nil {
			errs = append(errs, fmt.Errorf("membrane seed: company %d: %w", cid, err))
		}
	}
	if taskID > 0 {
		if _, err := s.membraneSyncTaskID(ctx, taskID); err != nil {
			errs = append(errs, fmt.Errorf("membrane seed: task %d: %w", taskID, err))
		}
	}
	err := errors.Join(errs...)
	if err != nil {
		log.Printf("[membrane] seed after change: %v", err)
	}
	return err
}

// membraneSeedResult adds the seed error, if any, to a JSON response.
func membraneSeedResult(out map[string]any, err error) {
	if err != nil {
		out["membrane_seed_error"] = err.Error()
	}
}

// membraneSyncTask seeds t before it launches (launchTask).
func (s *Server) membraneSyncTask(t *Task) error {
	if t == nil {
		return nil
	}
	_, err := s.SyncTask(context.Background(), t.ID)
	return err
}

// membraneSyncAll seeds every company and every live task at startup.
// Errors are logged and reported in membraneStatus; they are not fatal
// because each task syncs again before its requests. It stops when ctx is
// done. ctx is passed in (not read from s.ctx, which New rewrites while this
// runs in the background).
func (s *Server) membraneSyncAll(ctx context.Context) error {
	sd := s.seeder()
	if sd == nil {
		return nil
	}
	var errs []error
	companies, err := s.m.pg.Companies().ListCompanies()
	if err != nil {
		errs = append(errs, fmt.Errorf("list companies: %w", err))
	}
	for _, c := range companies {
		if ctx.Err() != nil {
			break
		}
		if err := sd.company(c.ID); err != nil {
			errs = append(errs, fmt.Errorf("company %d: %w", c.ID, err))
		}
	}
	for _, t := range s.m.List() {
		if ctx.Err() != nil {
			break
		}
		if isTerminalStatus(t.lifecycleSnapshot().Status) {
			continue
		}
		if _, err := s.SyncTask(ctx, t.ID); err != nil {
			errs = append(errs, fmt.Errorf("task %s: %w", t.ID, err))
		}
	}
	err = errors.Join(errs...)
	msg := ""
	if err != nil {
		msg = fmt.Sprintf("startup seed sync: %d error(s): %v", len(errs), err)
		log.Printf("[membrane] %s", msg)
	}
	s.mem.seedErr.Store(&msg)
	return err
}

func (s *Server) membraneSyncTaskID(ctx context.Context, id int64) ([]int64, error) {
	sd := s.seeder()
	if sd == nil {
		return nil, nil
	}
	return sd.task(ctx, id)
}

// task seeds task id (its companies first) into the seeder's store and
// returns the task's company ids. The preview runs it over a dry-run store.
func (sd *seeder) task(ctx context.Context, id int64) ([]int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := sd.s
	pg := s.m.pg
	task, err := pg.GetTask(id)
	if err != nil {
		return nil, fmt.Errorf("membrane seed: load task: %w", err)
	}
	if task == nil {
		return nil, nil // deleted or unknown: nothing to seed
	}
	companies := slices.Clone(task.CompanyIDs)
	var legacy sql.NullInt64
	if err := pg.QueryRow(`SELECT company_id FROM tasks WHERE id=$1`, id).Scan(&legacy); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("membrane seed: load task company: %w", err)
	}
	if legacy.Valid && legacy.Int64 > 0 && !slices.Contains(companies, legacy.Int64) {
		companies = append(companies, legacy.Int64)
	}
	slices.Sort(companies)
	for _, cid := range companies {
		if err := sd.company(cid); err != nil {
			return nil, fmt.Errorf("membrane seed: company %d: %w", cid, err)
		}
	}

	prov := membrane.Provenance{CompanyIDs: companies, TaskIDs: []int64{id}, Source: "seed"}
	scope, err := pg.Assets().ListTaskScope(id)
	if err != nil {
		return nil, fmt.Errorf("membrane seed: load task scope: %w", err)
	}
	target := ""
	if _, host, _, ok := parseTarget(task.Description + " " + task.Goal); ok && host != s.llmHost() {
		target = host
	}
	// Pass 1: keywords and declared roots, so pass 2 can classify hosts.
	// Declared: a root_domain row not added automatically (source manual,
	// set by the UI, or agent, set by add_task_scope; insertAssets writes
	// auto), and the root of the task's target host. A shared multi-tenant
	// root (membrane.IsSharedTenantRoot) is never declared.
	for _, r := range scope {
		var err error
		switch {
		case r.Kind == "keyword" || r.Kind == "icp":
			err = sd.keyword(r.Value, prov)
		case r.Kind == "root_domain" && r.Source != "auto":
			err = sd.declareRoot(r.Domain, prov)
		}
		if err != nil {
			return nil, fmt.Errorf("membrane seed: task scope %s row %d: %w", r.Kind, r.ID, err)
		}
	}
	if target != "" {
		// The task's target is operator-declared scope: its root is a
		// client root unless it is a shared multi-tenant root.
		if err := sd.declareHostRoot(target, prov); err != nil {
			return nil, fmt.Errorf("membrane seed: task target: %w", err)
		}
	}
	// Pass 2: hosts (classified client / third party) and networks.
	for _, r := range scope {
		var err error
		switch r.Kind {
		case "root_domain", "subdomain":
			mode := hostDeclared
			if r.Source == "auto" {
				mode = hostAuto
			}
			err = sd.classifiedHost(r.Domain, prov, mode)
		case "ip", "cidr":
			err = sd.network(r.Net, prov)
		}
		if err != nil {
			return nil, fmt.Errorf("membrane seed: task scope %s row %d: %w", r.Kind, r.ID, err)
		}
	}

	creds, err := pg.TaskCredentials(id)
	if err != nil {
		return nil, fmt.Errorf("membrane seed: load credentials: %w", err)
	}
	for _, c := range creds {
		if err := sd.credential(c.Domain, c.Username, c.Password, prov); err != nil {
			return nil, fmt.Errorf("membrane seed: credential %d: %w", c.ID, err)
		}
	}

	if err := sd.assets(`$1::bigint = ANY(task_ids)`, id, prov); err != nil {
		return nil, fmt.Errorf("membrane seed: task assets: %w", err)
	}
	if _, _, err := sd.e.ToModel(task.Description+"\n"+task.Goal, prov); err != nil {
		return nil, fmt.Errorf("membrane seed: task text: %w", err)
	}
	return companies, nil
}

// seeder enrols seed values into the server's store.
type seeder struct {
	s  *Server
	st *membrane.Store
	e  *membrane.Engine
	// seen dedupes tenant labels within one sync (each Enroll of an
	// existing keyword costs a re-mint scan).
	seen map[string]bool
	// opKeywords are the operator keywords seen in this sync (company
	// names, scope keyword/icp rows, declared roots' brand variants): the
	// only keywords that can make a root client space.
	opKeywords []string
}

// seeder returns nil when the membrane is off or not initialised: nothing to
// seed (remote providers then fail closed or run under the override).
func (s *Server) seeder() *seeder {
	if s.mem.store == nil || s.mem.engine == nil || s.m == nil || s.m.pg == nil {
		return nil
	}
	return &seeder{s: s, st: s.mem.store, e: s.mem.engine, seen: map[string]bool{}}
}

// company seeds one company's name, brand variants, scope and assets with
// provenance {company}.
func (sd *seeder) company(cid int64) error {
	cs := sd.s.m.pg.Companies()
	c, err := cs.GetCompany(cid)
	if err != nil {
		return fmt.Errorf("load company: %w", err)
	}
	if c == nil {
		return nil
	}
	prov := membrane.Provenance{CompanyIDs: []int64{cid}, Source: "seed"}
	if err := sd.keyword(c.Name, prov); err != nil {
		return fmt.Errorf("company name: %w", err)
	}
	rules, err := cs.GetScope(cid)
	if err != nil {
		return fmt.Errorf("load company scope: %w", err)
	}
	// A company scope domain is operator-declared: its root is a client root
	// unless it is a shared multi-tenant root (acme.okta.com declares the
	// tenant, not okta.com).
	for _, r := range rules {
		var err error
		switch r.Kind {
		case "keyword", "icp":
			err = sd.keyword(r.Value, prov)
		case "domain":
			err = sd.declareHostRoot(r.Domain, prov)
		case "ip", "cidr":
			err = sd.network(r.Net, prov)
		}
		if err != nil {
			return fmt.Errorf("company scope %s row %d: %w", r.Kind, r.ID, err)
		}
	}
	if err := sd.assets(`company_id = $1::bigint`, cid, prov); err != nil {
		return fmt.Errorf("company assets: %w", err)
	}
	return nil
}

// assets seeds the distinct host names and IPs of the assets matching
// where (one bigint parameter $1), in keyset-paginated batches. Only those
// columns are read. A host under a client root only ensures the root
// (subdomains alias through it); a third-party host contributes its tenant
// label (see host).
func (sd *seeder) assets(where string, arg int64, prov membrane.Provenance) error {
	q := `
SELECT v FROM (
    SELECT domain AS v FROM assets WHERE ` + where + ` AND COALESCE(domain,'') <> ''
    UNION
    SELECT root_domain AS v FROM assets WHERE ` + where + ` AND COALESCE(root_domain,'') <> ''
    UNION
    SELECT ip AS v FROM assets WHERE ` + where + ` AND COALESCE(ip,'') <> ''
) x WHERE v > $2 ORDER BY v LIMIT $3`
	last := ""
	for {
		rows, err := sd.s.m.pg.Query(q, arg, last, seedAssetBatch)
		if err != nil {
			return err
		}
		var vals []string
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				rows.Close()
				return err
			}
			vals = append(vals, v)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, v := range vals {
			if err := sd.classifiedHost(v, prov, hostAsset); err != nil {
				return err
			}
		}
		if len(vals) < seedAssetBatch {
			return nil
		}
		last = vals[len(vals)-1]
	}
}

// keyword enrols a term (company name, scope keyword, ICP) and its brand
// variants as org keywords. Short variants are dropped by BrandVariants;
// short terms stay out of the literal scan by the store's own rules (R3,
// R10).
func (sd *seeder) keyword(v string, prov membrane.Provenance) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	vs := append([]string{v}, membrane.BrandVariants(v)...)
	sd.opKeywords = append(sd.opKeywords, vs...)
	return sd.keywords(prov, vs...)
}

func (sd *seeder) keywords(prov membrane.Provenance, vs ...string) error {
	for _, v := range vs {
		if _, err := sd.st.Enroll(membrane.KindOrg, v, prov); err != nil {
			return err
		}
	}
	return nil
}

// host enrols a host name or an IP address (see classifiedHost).
func (sd *seeder) host(h string, prov membrane.Provenance) error {
	return sd.classifiedHost(h, prov, hostDeclared)
}

// hostMode says how far a host is trusted as client data.
type hostMode int

const (
	// hostDeclared: operator-declared (company/task scope added by a person
	// or the agent's add_task_scope, credentials, the task target): a
	// third-party host contributes its tenant label.
	hostDeclared hostMode = iota
	// hostAuto: recorded automatically (auto task_scope rows): a
	// third-party host is left alone.
	hostAuto
	// hostAsset: an asset host: like hostAuto, and under a client root only
	// the root is enrolled (subdomains alias through it).
	hostAsset
)

// classifiedHost enrols an IP address, or classifies a host name by its
// registrable root (Task 9 fix C1):
//   - client root: already enrolled, or its label carries an operator
//     keyword (then opted in with EnrollRoot) -> the host is enrolled as a
//     domain (hostAsset: just the root);
//   - otherwise third party (okta.com under acme.okta.com): no domain or root
//     is ever enrolled for it, so derivation can never map a model's host
//     onto another tenant. Only for an operator-declared host (hostDeclared)
//     the tenant label, if distinctive, is enrolled as an org keyword so
//     acme.okta.com reaches the model as org-xxxx.okta.com; auto-recorded
//     hosts and assets (graph.microsoft.com, fonts.googleapis.com...) are
//     left alone, since their labels are ordinary words (fix I-B).
//
// Values that are not a registrable host name (single labels such as
// "localhost", a bare public suffix, URLs that do not parse) are skipped:
// refusing the whole sync over one would block the task for good.
func (sd *seeder) classifiedHost(h string, prov membrane.Provenance, mode hostMode) error {
	h = hostOf(h)
	if h == "" {
		return nil
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return sd.ip(a, prov)
	}
	h, root, ok := registrableRoot(h)
	if !ok {
		return nil
	}
	client, err := sd.clientRoot(root, prov)
	if err != nil {
		return err
	}
	if !client {
		if mode != hostDeclared {
			return nil
		}
		return sd.tenantLabel(h, root, prov)
	}
	if mode == hostAsset {
		h = root
	}
	_, err = sd.st.Enroll(membrane.KindDomain, h, prov)
	return err
}

// clientRoot reports whether root is client space, opting in a root whose
// label carries an operator keyword (company names, scope keyword/icp rows
// and their brand variants; never tenant labels) with its brand variant.
func (sd *seeder) clientRoot(root string, prov membrane.Provenance) (bool, error) {
	if membrane.IsSharedTenantRoot(root) {
		return false, nil
	}
	if sd.st.HasRoot(root) {
		return true, nil
	}
	label, _, _ := strings.Cut(root, ".")
	if !membrane.LabelHasKeyword(label, sd.opKeywords) {
		return false, nil
	}
	return true, sd.enrollRoot(root, prov)
}

// declareRoot opts in a root the operator declared (a company scope domain
// or a non-auto task root_domain row that is a registrable root) and enrols
// its brand variant, unless it is a shared multi-tenant root. A non-root
// value goes through classification.
func (sd *seeder) declareRoot(d string, prov membrane.Provenance) error {
	h, root, ok := registrableRoot(hostOf(d))
	if !ok {
		return nil
	}
	if h != root {
		return sd.host(h, prov)
	}
	return sd.declareHostRoot(h, prov)
}

// declareHostRoot opts in the registrable root of a host the operator
// declared as a target (any host of a task's target/URL fields), then
// enrols the host. Under a shared multi-tenant root (okta.com,
// amazonaws.com... see membrane.IsSharedTenantRoot) the root is never the
// client's: the host gets the third-party tenant-label rule instead.
func (sd *seeder) declareHostRoot(d string, prov membrane.Provenance) error {
	h, root, ok := registrableRoot(hostOf(d))
	if !ok {
		return nil
	}
	if membrane.IsSharedTenantRoot(root) {
		return sd.tenantLabel(h, root, prov)
	}
	if err := sd.enrollRoot(root, prov); err != nil {
		return err
	}
	if h == root {
		return nil
	}
	_, err := sd.st.Enroll(membrane.KindDomain, h, prov)
	return err
}

func (sd *seeder) enrollRoot(root string, prov membrane.Provenance) error {
	if _, err := sd.st.EnrollRoot(root, prov); err != nil {
		return err
	}
	// Brand inference only from client roots (Task 9 fix I1).
	vs := membrane.BrandVariants(root)
	sd.opKeywords = append(sd.opKeywords, vs...)
	return sd.keywords(prov, vs...)
}

// tenantLabel enrols the distinctive label of a third-party host nearest to
// its root (acme in acme.okta.com, acme in acme.my.salesforce.com) as an
// org keyword. Generic labels (www, login, portal...), labels shorter than 4
// or containing digits (regions, shards, hashes) are not tenant names.
func (sd *seeder) tenantLabel(h, root string, prov membrane.Provenance) error {
	prefix := strings.TrimSuffix(strings.TrimSuffix(h, root), ".")
	if prefix == "" {
		return nil
	}
	labels := strings.Split(prefix, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		l := labels[i]
		if !distinctiveLabel(l) {
			continue
		}
		if sd.seen[l] {
			return nil
		}
		sd.seen[l] = true
		_, err := sd.st.Enroll(membrane.KindOrg, l, prov)
		return err
	}
	return nil
}

// genericLabels are host labels that name a function, not a tenant.
var genericLabels = map[string]bool{
	"www": true, "api": true, "apis": true, "app": true, "apps": true, "login": true, "logon": true,
	"signin": true, "portal": true, "auth": true, "oauth": true, "sso": true, "idp": true, "mail": true,
	"webmail": true, "smtp": true, "imap": true, "admin": true, "test": true, "tests": true, "dev": true,
	"devel": true, "stage": true, "staging": true, "prod": true, "production": true, "preprod": true,
	"uat": true, "qa": true, "sandbox": true, "cdn": true, "static": true, "assets": true, "media": true,
	"images": true, "img": true, "files": true, "download": true, "downloads": true, "web": true,
	"secure": true, "vpn": true, "remote": true, "gateway": true, "proxy": true, "edge": true, "my": true,
	"account": true, "accounts": true, "console": true, "dashboard": true, "help": true, "support": true,
	"docs": true, "status": true, "blog": true, "shop": true, "store": true, "cloud": true, "online": true,
	"service": true, "services": true, "public": true, "internal": true, "beta": true, "demo": true,
	"git": true, "jira": true, "wiki": true, "confluence": true, "mobile": true, "home": true, "info": true,
	"news": true, "events": true, "community": true, "forum": true, "data": true, "analytics": true,
	"metrics": true, "monitor": true, "monitoring": true, "backup": true, "storage": true, "s3": true,
	"default": true, "global": true, "europe": true, "east": true, "west": true, "north": true,
	"south": true, "central": true, "origin": true, "mx": true, "ns": true, "autodiscover": true,
	"lyncdiscover": true, "enterpriseregistration": true, "enterpriseenrollment": true, "selector": true,
}

func distinctiveLabel(l string) bool {
	if utf8.RuneCountInString(l) < 4 || genericLabels[l] || strings.HasPrefix(l, "xn--") {
		return false
	}
	return !strings.ContainsFunc(l, unicode.IsDigit)
}

func (sd *seeder) ip(a netip.Addr, prov membrane.Provenance) error {
	a = a.Unmap()
	kind := membrane.KindIPv4
	if a.Is6() {
		kind = membrane.KindIPv6
	}
	_, err := sd.st.Enroll(kind, a.String(), prov) // non-public: returned unchanged
	return err
}

// network enrols a scope ip/cidr value: a single host as an address, a wider
// IPv4 prefix as a pre-allocated alias block. IPv6 prefixes are aliased per
// address by the detectors; IPv4 prefixes wider than /8 are refused by the
// store and skipped here (their addresses are still aliased per /24).
func (sd *seeder) network(v string, prov membrane.Provenance) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	p, err := netip.ParsePrefix(v)
	if err != nil {
		if a, err := netip.ParseAddr(v); err == nil {
			return sd.ip(a, prov)
		}
		return nil
	}
	if p.Bits() == p.Addr().BitLen() {
		return sd.ip(p.Addr(), prov)
	}
	if !p.Addr().Unmap().Is4() || p.Bits() < 8 {
		return nil
	}
	return sd.st.SeedCIDR(p, prov)
}

// credential enrols a task credential: its domain, the username (an email
// address as an email) and the password. Empty fields are skipped.
func (sd *seeder) credential(domain, user, pass string, prov membrane.Provenance) error {
	if err := sd.host(domain, prov); err != nil {
		return err
	}
	if user = strings.TrimSpace(user); user != "" {
		enrolled := false
		if strings.Contains(user, "@") {
			if _, err := sd.st.Enroll(membrane.KindEmail, user, prov); err == nil {
				enrolled = true
			}
		}
		if !enrolled {
			if _, err := sd.st.Enroll(membrane.KindUsername, user, prov); err != nil {
				return err
			}
		}
	}
	if pass != "" {
		if _, err := sd.st.Enroll(membrane.KindPassword, pass, prov); err != nil {
			return err
		}
	}
	return nil
}

// hostOf extracts the host from a domain, host:port, URL or "*.domain"
// value, lowercased.
func hostOf(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil {
			return ""
		}
		v = u.Hostname()
	} else if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	}
	v = strings.TrimPrefix(v, "*.")
	v = strings.Trim(v, "[]")
	return strings.TrimSuffix(strings.ToLower(v), ".")
}

// registrableRoot returns h in ASCII (punycode) form and its registrable
// root; ok is false when h is not a host name under a registrable domain.
func registrableRoot(h string) (host, root string, ok bool) {
	if strings.ContainsAny(h, " \t\r\n/@:") {
		return "", "", false
	}
	a, err := idna.Punycode.ToASCII(h)
	if err != nil {
		return "", "", false
	}
	a = strings.ToLower(a)
	r, err := publicsuffix.EffectiveTLDPlusOne(a)
	if err != nil {
		return "", "", false
	}
	return a, r, true
}
