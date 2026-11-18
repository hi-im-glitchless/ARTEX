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

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/Autumn-27/artex/membrane"
)

// Seeding the membrane dictionary (spec §7.1): before a task's first LLM
// request, and again at most every 30s while it runs (membrane.Syncer), the
// client values the database already knows are enrolled, so they are aliased
// even where no structural detector would find them:
//   - linked companies: name and its brand variants, company_scope rows
//     (domain + brand variant, ip, cidr, keyword, icp) and the root domains
//     and IPs of the company's assets;
//   - the task: task_scope rows, task_credentials (domain, username,
//     password), the target host of the description/goal, the root domains
//     and IPs of its own assets, and the structural detections in its
//     description and goal (engine.ToModel, output discarded).
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
// because each task syncs again before its requests.
func (s *Server) membraneSyncAll() error {
	sd := s.seeder()
	if sd == nil {
		return nil
	}
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	for _, r := range scope {
		var err error
		switch r.Kind {
		case "root_domain":
			err = sd.host(r.Domain, prov)
			if err == nil && r.Source != "auto" {
				// Brand inference only from deliberately added roots: an
				// auto row may be a third-party root an agent recorded.
				err = sd.keywords(prov, membrane.BrandVariants(r.Domain)...)
			}
		case "subdomain":
			err = sd.host(r.Domain, prov)
		case "ip", "cidr":
			err = sd.network(r.Net, prov)
		case "keyword", "icp":
			err = sd.keyword(r.Value, prov)
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

	if _, host, _, ok := parseTarget(task.Description + " " + task.Goal); ok && host != s.llmHost() {
		if err := sd.host(host, prov); err != nil {
			return nil, fmt.Errorf("membrane seed: task target: %w", err)
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
}

// seeder returns nil when the membrane is off or not initialised: nothing to
// seed (remote providers then fail closed or run under the override).
func (s *Server) seeder() *seeder {
	if s.mem.store == nil || s.mem.engine == nil || s.m == nil || s.m.pg == nil {
		return nil
	}
	return &seeder{s: s, st: s.mem.store, e: s.mem.engine}
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
	for _, r := range rules {
		var err error
		switch r.Kind {
		case "domain":
			if err = sd.host(r.Domain, prov); err == nil {
				err = sd.keywords(prov, membrane.BrandVariants(r.Domain)...)
			}
		case "ip", "cidr":
			err = sd.network(r.Net, prov)
		case "keyword", "icp":
			err = sd.keyword(r.Value, prov)
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

// assets seeds the distinct root domains and IPs of the assets matching
// where (one bigint parameter $1), in keyset-paginated batches. Only those
// two columns are read: subdomains alias through their root, and the scan
// stays cheap on a large asset table.
func (sd *seeder) assets(where string, arg int64, prov membrane.Provenance) error {
	q := `
SELECT v FROM (
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
			if err := sd.host(v, prov); err != nil {
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
	return sd.keywords(prov, append([]string{v}, membrane.BrandVariants(v)...)...)
}

func (sd *seeder) keywords(prov membrane.Provenance, vs ...string) error {
	for _, v := range vs {
		if _, err := sd.st.Enroll(membrane.KindOrg, v, prov); err != nil {
			return err
		}
	}
	return nil
}

// host enrols a domain (its root comes with it) or an IP address. Values
// that are not a registrable host name (single labels such as "localhost",
// a bare public suffix, URLs that do not parse) are skipped: the store
// cannot alias them as domains, and refusing the whole sync over one would
// block the task for good.
func (sd *seeder) host(h string, prov membrane.Provenance) error {
	h = hostOf(h)
	if h == "" {
		return nil
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return sd.ip(a, prov)
	}
	if !registrableHost(h) {
		return nil
	}
	_, err := sd.st.Enroll(membrane.KindDomain, h, prov)
	return err
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

// registrableHost reports whether h is a host name under a registrable
// domain (what Store.Enroll(KindDomain) accepts).
func registrableHost(h string) bool {
	if strings.ContainsAny(h, " \t\r\n/@:") {
		return false
	}
	a, err := idna.Punycode.ToASCII(h)
	if err != nil {
		return false
	}
	_, err = publicsuffix.EffectiveTLDPlusOne(a)
	return err == nil
}
