package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/membrane"
)

const membraneUsage = "usage: artex membrane verify --task <id> [--keys-dir <dir>]"

// runMembrane implements `artex membrane verify --task <id>`: it re-runs the
// pre-send leak check over the task's recorded wire requests and checks the
// audit chain, printing `checked=N failed=M chain=ok|broken`. It exits 0
// only when nothing failed and the chain is intact, 1 on a failure or an
// error, 2 on a usage error. It reads the database the server uses
// (ARTEX_PG_DSN or config.json) and the server's membrane keys (env, or
// membrane.keys in the key dir); it never generates keys and never writes
// the mapping table. Output carries counts, record ids and kinds only.
func runMembrane(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprintln(stderr, membraneUsage)
		return 2
	}
	fs := flag.NewFlagSet("membrane verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	task := fs.String("task", "", "task id to verify")
	keyDir := fs.String("keys-dir", config.BaseDir(), "directory holding membrane.keys (the server's key dir) when the env keys are not set")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	id, err := strconv.ParseInt(strings.TrimSpace(*task), 10, 64)
	if *task == "" || err != nil || id <= 0 {
		fmt.Fprintln(stderr, "membrane verify: --task <numeric id> is required")
		fmt.Fprintln(stderr, membraneUsage)
		return 2
	}
	if !membrane.KeysConfigured(*keyDir) {
		fmt.Fprintf(stderr, "membrane verify: membrane keys missing: set %s and %s, or run from the directory holding %s (--keys-dir)\n",
			membrane.EnvEncKey, membrane.EnvHMACKey, filepath.Join(*keyDir, membrane.KeysFileName))
		return 1
	}
	enc, mac, _, err := membrane.LoadKeysSource(*keyDir)
	if err != nil {
		fmt.Fprintf(stderr, "membrane verify: keys: %v\n", err)
		return 1
	}
	dsn, _, err := db.DSN()
	if err != nil {
		fmt.Fprintf(stderr, "membrane verify: database: %v\n", err)
		return 1
	}
	pg, err := db.Open(dsn)
	if err != nil {
		fmt.Fprintf(stderr, "membrane verify: open database: %v\n", err)
		return 1
	}
	defer pg.Close()
	st, err := membrane.OpenReadOnlyStore(pg, enc, mac)
	if err != nil {
		fmt.Fprintf(stderr, "membrane verify: open mapping: %v\n", err)
		return 1
	}
	res, err := membrane.VerifyTask(membrane.NewEngine(st, nil), pg, strconv.FormatInt(id, 10))
	if err != nil {
		fmt.Fprintf(stderr, "membrane verify: %v\n", err)
		return 1
	}
	chain := "ok"
	if !res.ChainOK {
		chain = "broken"
	}
	fmt.Fprintf(stdout, "checked=%d failed=%d chain=%s\n", res.Checked, res.Failed, chain)
	if res.NoRaw > 0 || res.Unmembraned > 0 {
		fmt.Fprintf(stdout, "no_raw=%d unmembraned=%d\n", res.NoRaw, res.Unmembraned)
	}
	if res.Failed > 0 {
		ids := make([]string, len(res.FailedIDs))
		for i, x := range res.FailedIDs {
			ids[i] = strconv.FormatInt(x, 10)
		}
		kinds := make([]string, 0, len(res.FailedKinds))
		for k, n := range res.FailedKinds {
			kinds = append(kinds, fmt.Sprintf("%s:%d", k, n))
		}
		sort.Strings(kinds)
		fmt.Fprintf(stdout, "failed_ids=%s kinds=%s\n", strings.Join(ids, ","), strings.Join(kinds, ","))
	}
	if !res.ChainOK {
		fmt.Fprintf(stdout, "chain_first_bad_id=%d\n", res.ChainFirstBadID)
	}
	if !res.OK() {
		return 1
	}
	return 0
}
