package db

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

// Advisory lock keys (distinct from the schema/test locks 7337741001/2).
const (
	membraneEventLockKey int64 = 7337741099
	membraneBlockLockKey int64 = 7337741098
)

// MembraneEntry is one original<->alias mapping row. The original is stored
// only as an HMAC (lookup) and AES-GCM ciphertext.
type MembraneEntry struct {
	ID           int64
	Kind         string
	OriginalHMAC string
	OriginalEnc  []byte
	Alias        string
	// RetiredAliases are earlier aliases of this original, kept for reverse
	// lookup after a re-mint (oldest first).
	RetiredAliases []string
	Source         string
	CompanyIDs     []int64
	TaskIDs        []int64
	FirstSeen      time.Time
	LastSeen       time.Time
}

// MembraneBlock maps a real CIDR prefix to its alias block in 240.0.0.0/4.
type MembraneBlock struct {
	RealPrefix  string
	AliasPrefix string
	Bits        int
}

// MembraneEvent is one append-only audit row, hash-chained to its predecessor.
type MembraneEvent struct {
	ID            int64
	TS            time.Time
	TaskID        string
	Session       string
	Role          string
	Profile       string
	Direction     string
	Counts        map[string]int
	Enrolled      int
	Flags         []string
	Blocked       bool
	BlockReason   string
	RequestSHA256 string
	PrevHash      string
	Hash          string
}

// int64sJSON renders ids as a JSON array so it can be cast to bigint[] in SQL
// without depending on driver array encoding.
func int64sJSON(ids []int64) string {
	if ids == nil {
		ids = []int64{}
	}
	b, _ := json.Marshal(ids)
	return string(b)
}

func decodeInt64s(raw []byte) []int64 {
	out := []int64{}
	_ = json.Unmarshal(raw, &out)
	return out
}

const membraneEntryCols = `id, kind, original_hmac, original_enc, alias, source,
	to_jsonb(company_ids), to_jsonb(task_ids), first_seen, last_seen, to_jsonb(retired_aliases)`

func scanMembraneEntry(sc interface{ Scan(...any) error }) (MembraneEntry, error) {
	var e MembraneEntry
	var cj, tj, rj []byte
	if err := sc.Scan(&e.ID, &e.Kind, &e.OriginalHMAC, &e.OriginalEnc, &e.Alias, &e.Source,
		&cj, &tj, &e.FirstSeen, &e.LastSeen, &rj); err != nil {
		return MembraneEntry{}, err
	}
	e.CompanyIDs, e.TaskIDs = decodeInt64s(cj), decodeInt64s(tj)
	e.RetiredAliases = []string{}
	if err := json.Unmarshal(rj, &e.RetiredAliases); err != nil {
		return MembraneEntry{}, fmt.Errorf("membrane entry %d: retired aliases: %w", e.ID, err)
	}
	return e, nil
}

// InsertMembraneEntry inserts e; on conflict (kind, original_hmac) it keeps the
// existing alias and ciphertext, merges company/task provenance and returns
// the stored row.
func (d *DB) InsertMembraneEntry(e *MembraneEntry) (MembraneEntry, error) {
	src := e.Source
	if src == "" {
		src = "auto"
	}
	row := d.QueryRow(`
INSERT INTO membrane_entries(kind, original_hmac, original_enc, alias, source, company_ids, task_ids)
VALUES ($1,$2,$3,$4,$5,
        ARRAY(SELECT jsonb_array_elements_text($6::jsonb)::bigint),
        ARRAY(SELECT jsonb_array_elements_text($7::jsonb)::bigint))
ON CONFLICT (kind, original_hmac) DO UPDATE SET
    company_ids = ARRAY(SELECT DISTINCT x FROM unnest(membrane_entries.company_ids || EXCLUDED.company_ids) x ORDER BY x),
    task_ids    = ARRAY(SELECT DISTINCT x FROM unnest(membrane_entries.task_ids || EXCLUDED.task_ids) x ORDER BY x),
    last_seen   = now()
RETURNING `+membraneEntryCols,
		e.Kind, e.OriginalHMAC, e.OriginalEnc, e.Alias, src,
		int64sJSON(e.CompanyIDs), int64sJSON(e.TaskIDs))
	out, err := scanMembraneEntry(row)
	if err != nil {
		return MembraneEntry{}, fmt.Errorf("insert membrane entry: %w", err)
	}
	return out, nil
}

// UpdateMembraneEntryAlias replaces the alias of entry id with newAlias and,
// in the same statement, appends the previous alias to retired_aliases. It is
// a no-op when the alias is already newAlias.
func (d *DB) UpdateMembraneEntryAlias(id int64, newAlias string) error {
	res, err := d.Exec(`
UPDATE membrane_entries SET
    retired_aliases = CASE WHEN alias = $2 THEN retired_aliases
                           ELSE array_append(retired_aliases, alias) END,
    alias = $2,
    last_seen = now()
WHERE id = $1`, id, newAlias)
	if err != nil {
		return fmt.Errorf("update membrane entry %d alias: %w", id, err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("update membrane entry %d alias: %w", id, sql.ErrNoRows)
	}
	return nil
}

// ListMembraneEntries returns every mapping row ordered by id.
func (d *DB) ListMembraneEntries() ([]MembraneEntry, error) {
	rows, err := d.Query(`SELECT ` + membraneEntryCols + ` FROM membrane_entries ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MembraneEntry
	for rows.Next() {
		e, err := scanMembraneEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AllocateMembraneBlock returns the alias block for realPrefix, allocating the
// lowest bits-aligned block in 240.0.0.0/4 not overlapping any existing alias
// block. Idempotent per realPrefix and safe under concurrency.
func (d *DB) AllocateMembraneBlock(realPrefix string, bits int) (string, error) {
	if bits < 4 || bits > 32 {
		return "", fmt.Errorf("membrane block: unsupported prefix length %d", bits)
	}
	tx, err := d.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, membraneBlockLockKey); err != nil {
		return "", err
	}
	var existing string
	err = tx.QueryRow(`SELECT alias_prefix FROM membrane_ip_blocks WHERE real_prefix=$1`, realPrefix).Scan(&existing)
	if err == nil {
		return existing, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return "", err
	}

	rows, err := tx.Query(`SELECT alias_prefix FROM membrane_ip_blocks`)
	if err != nil {
		return "", err
	}
	type span struct{ lo, hi uint64 }
	var used []span
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return "", err
		}
		p, err := netip.ParsePrefix(s)
		if err != nil || !p.Addr().Is4() {
			rows.Close()
			return "", fmt.Errorf("membrane block: corrupt alias prefix %q", s)
		}
		a := p.Addr().As4()
		lo := uint64(a[0])<<24 | uint64(a[1])<<16 | uint64(a[2])<<8 | uint64(a[3])
		used = append(used, span{lo, lo + 1<<(32-uint(p.Bits())) - 1})
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	rows.Close()

	size := uint64(1) << (32 - uint(bits))
	const top = uint64(0xFFFFFFFF)
	var alias string
	for start := uint64(0xF0000000); start+size-1 <= top; start += size {
		end := start + size - 1
		clash := false
		for _, u := range used {
			if start <= u.hi && u.lo <= end {
				clash = true
				break
			}
		}
		if !clash {
			alias = fmt.Sprintf("%d.%d.%d.%d/%d", start>>24&0xFF, start>>16&0xFF, start>>8&0xFF, start&0xFF, bits)
			break
		}
	}
	if alias == "" {
		return "", fmt.Errorf("membrane block: 240.0.0.0/4 alias space exhausted")
	}
	if _, err := tx.Exec(`INSERT INTO membrane_ip_blocks(real_prefix, alias_prefix, bits) VALUES ($1,$2,$3)`,
		realPrefix, alias, bits); err != nil {
		return "", err
	}
	return alias, tx.Commit()
}

// ListMembraneBlocks returns all allocated blocks ordered by alias.
func (d *DB) ListMembraneBlocks() ([]MembraneBlock, error) {
	rows, err := d.Query(`SELECT real_prefix, alias_prefix, bits FROM membrane_ip_blocks ORDER BY alias_prefix::cidr`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MembraneBlock
	for rows.Next() {
		var b MembraneBlock
		if err := rows.Scan(&b.RealPrefix, &b.AliasPrefix, &b.Bits); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// membraneCanonical is the hashed form of an event: fixed field order, every
// field except Hash.
type membraneCanonical struct {
	ID            int64          `json:"id"`
	TS            string         `json:"ts"`
	TaskID        string         `json:"task_id"`
	Session       string         `json:"session"`
	Role          string         `json:"role"`
	Profile       string         `json:"profile"`
	Direction     string         `json:"direction"`
	Counts        map[string]int `json:"counts"`
	Enrolled      int            `json:"enrolled"`
	Flags         []string       `json:"flags"`
	Blocked       bool           `json:"blocked"`
	BlockReason   string         `json:"block_reason"`
	RequestSHA256 string         `json:"request_sha256"`
	PrevHash      string         `json:"prev_hash"`
}

func membraneEventHash(ev *MembraneEvent) string {
	c := membraneCanonical{
		ID: ev.ID, TS: ev.TS.UTC().Format(time.RFC3339Nano), TaskID: ev.TaskID,
		Session: ev.Session, Role: ev.Role, Profile: ev.Profile, Direction: ev.Direction,
		Counts: ev.Counts, Enrolled: ev.Enrolled, Flags: ev.Flags, Blocked: ev.Blocked,
		BlockReason: ev.BlockReason, RequestSHA256: ev.RequestSHA256, PrevHash: ev.PrevHash,
	}
	if c.Counts == nil {
		c.Counts = map[string]int{}
	}
	if c.Flags == nil {
		c.Flags = []string{}
	}
	b, _ := json.Marshal(c)
	h := sha256.New()
	h.Write([]byte(ev.PrevHash))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// AppendMembraneEvent appends ev to the chain. It fills ID, TS (when zero),
// PrevHash and Hash. The table has no update or delete path in Go.
func (d *DB) AppendMembraneEvent(ev *MembraneEvent) error {
	tx, err := d.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, membraneEventLockKey); err != nil {
		return err
	}
	var prev string
	err = tx.QueryRow(`SELECT hash FROM membrane_events ORDER BY id DESC LIMIT 1`).Scan(&prev)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	var id int64
	if err := tx.QueryRow(`SELECT nextval(pg_get_serial_sequence('membrane_events','id'))`).Scan(&id); err != nil {
		return err
	}
	if ev.TS.IsZero() {
		ev.TS = time.Now()
	}
	ev.TS = ev.TS.UTC().Truncate(time.Microsecond) // PG timestamptz precision
	if ev.Counts == nil {
		ev.Counts = map[string]int{}
	}
	if ev.Flags == nil {
		ev.Flags = []string{}
	}
	ev.ID, ev.PrevHash = id, prev
	ev.Hash = membraneEventHash(ev)
	counts, _ := json.Marshal(ev.Counts)
	flags, _ := json.Marshal(ev.Flags)
	if _, err := tx.Exec(`
INSERT INTO membrane_events(id, ts, task_id, session, role, profile, direction, counts, enrolled,
    flags, blocked, block_reason, request_sha256, prev_hash, hash)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10::jsonb,$11,$12,$13,$14,$15)`,
		ev.ID, ev.TS, ev.TaskID, ev.Session, ev.Role, ev.Profile, ev.Direction, string(counts),
		ev.Enrolled, string(flags), ev.Blocked, ev.BlockReason, ev.RequestSHA256, ev.PrevHash, ev.Hash); err != nil {
		return err
	}
	return tx.Commit()
}

const membraneEventCols = `id, ts, task_id, session, role, profile, direction, counts, enrolled,
	flags, blocked, block_reason, request_sha256, prev_hash, hash`

func scanMembraneEvent(sc interface{ Scan(...any) error }) (MembraneEvent, error) {
	var ev MembraneEvent
	var counts, flags []byte
	if err := sc.Scan(&ev.ID, &ev.TS, &ev.TaskID, &ev.Session, &ev.Role, &ev.Profile, &ev.Direction,
		&counts, &ev.Enrolled, &flags, &ev.Blocked, &ev.BlockReason, &ev.RequestSHA256,
		&ev.PrevHash, &ev.Hash); err != nil {
		return MembraneEvent{}, err
	}
	ev.TS = ev.TS.UTC()
	ev.Counts = map[string]int{}
	ev.Flags = []string{}
	_ = json.Unmarshal(counts, &ev.Counts)
	_ = json.Unmarshal(flags, &ev.Flags)
	if ev.Counts == nil {
		ev.Counts = map[string]int{}
	}
	if ev.Flags == nil {
		ev.Flags = []string{}
	}
	return ev, nil
}

// ListMembraneEvents pages events newest first. An empty taskID lists all.
func (d *DB) ListMembraneEvents(taskID string, page, size int) ([]MembraneEvent, int, error) {
	if page < 1 {
		page = 1
	}
	if size < 1 || size > 500 {
		size = 50
	}
	var total int
	if err := d.QueryRow(`SELECT count(*) FROM membrane_events WHERE ($1='' OR task_id=$1)`, taskID).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := d.Query(`SELECT `+membraneEventCols+` FROM membrane_events
		WHERE ($1='' OR task_id=$1) ORDER BY id DESC LIMIT $2 OFFSET $3`, taskID, size, (page-1)*size)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []MembraneEvent
	for rows.Next() {
		ev, err := scanMembraneEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, ev)
	}
	return out, total, rows.Err()
}

// VerifyMembraneChain walks every event in id order, recomputing hashes and
// checking prev-hash linkage. firstBadID is the first inconsistent row.
func (d *DB) VerifyMembraneChain() (ok bool, firstBadID int64, err error) {
	rows, err := d.Query(`SELECT ` + membraneEventCols + ` FROM membrane_events ORDER BY id`)
	if err != nil {
		return false, 0, err
	}
	defer rows.Close()
	prev := ""
	for rows.Next() {
		ev, err := scanMembraneEvent(rows)
		if err != nil {
			return false, 0, err
		}
		if ev.PrevHash != prev || membraneEventHash(&ev) != ev.Hash {
			return false, ev.ID, nil
		}
		prev = ev.Hash
	}
	return true, 0, rows.Err()
}

// PurgeMembraneCompany deletes entries referenced only by companyID (whose
// tasks, if any, are not linked to another company through tasks.company_id
// or a task_scope company row; hard-deleted tasks no longer count) and removes companyID from the provenance
// of the rest. Returns the number of deleted entries. The caller records the
// audit event and enforces the references guard.
func (d *DB) PurgeMembraneCompany(companyID int64) (int, error) {
	tx, err := d.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	res, err := tx.Exec(`
DELETE FROM membrane_entries e
WHERE e.company_ids = ARRAY[$1]::bigint[]
  AND NOT EXISTS (
      SELECT 1 FROM unnest(e.task_ids) t JOIN tasks k ON k.id = t
      WHERE (k.company_id IS NOT NULL AND k.company_id <> $1)
         OR EXISTS (SELECT 1 FROM task_scope ts WHERE ts.task_id = k.id
                    AND ts.kind = 'company' AND ts.company_id <> $1))`, companyID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := tx.Exec(`UPDATE membrane_entries SET company_ids = array_remove(company_ids, $1::bigint)
		WHERE $1::bigint = ANY(company_ids)`, companyID); err != nil {
		return 0, err
	}
	return int(n), tx.Commit()
}

// taskOfCompany matches a task t linked to company $1: through task_scope
// (kind company, how tasks are linked to companies) or the legacy
// tasks.company_id column.
const taskOfCompany = `(t.company_id=$1 OR EXISTS (SELECT 1 FROM task_scope ts
	WHERE ts.task_id=t.id AND ts.kind='company' AND ts.company_id=$1))`

// MembraneCompanyReferences counts the live real data that can still reach a
// prompt for companyID. Purge must be refused while any count is non-zero.
func (d *DB) MembraneCompanyReferences(companyID int64) (map[string]int, error) {
	out := map[string]int{}
	queries := []struct{ key, q string }{
		{"tasks", `SELECT count(*) FROM tasks t WHERE t.deleted_at IS NULL AND ` + taskOfCompany},
		{"assets", `SELECT count(*) FROM assets WHERE company_id=$1`},
		{"findings", `SELECT count(*) FROM findings f JOIN tasks t ON t.id=f.task_id
			WHERE t.deleted_at IS NULL AND ` + taskOfCompany},
		{"lessons", `SELECT count(*) FROM rsi_lessons WHERE company_id=$1`},
		{"scope", `SELECT count(*) FROM company_scope WHERE company_id=$1`},
	}
	for _, q := range queries {
		var n int
		if err := d.QueryRow(q.q, companyID).Scan(&n); err != nil {
			return nil, fmt.Errorf("membrane references %s: %w", q.key, err)
		}
		out[q.key] = n
	}
	return out, nil
}
