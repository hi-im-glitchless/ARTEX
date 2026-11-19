package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/membrane"
)

const membraneUsage = "usage: artex membrane verify --task <id> [--keys-dir <dir>]\n" +
	"  exit 0 pass, 1 fail or error, 2 usage, 3 inconclusive (forwarded requests without a recorded wire body)\n" +
	"  " + membrane.VerifyNote

// runMembrane implements `artex membrane verify --task <id>`: it re-runs the
// pre-send leak check over the task's recorded wire requests (paired with
// the task's audit events by the membrane request hash) and checks the
// audit chain. It prints `checked=N failed=M chain=ok|broken`, then
// `result=pass|fail|inconclusive forwarded=F paired=P unpaired=U`. Exit
// codes: 0 pass, 1 fail (a record failed or the chain is broken) or an
// error, 2 usage, 3 inconclusive (a forwarded request has no recorded wire
// body, so it could not be checked). It reads the database the server uses
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
	// Default: the server's key dir, ARTEX_JWT_KEY_DIR (/app/keys in Docker),
	// else the install dir.
	defKeyDir := strings.TrimSpace(os.Getenv("ARTEX_JWT_KEY_DIR"))
	if defKeyDir == "" {
		defKeyDir = config.BaseDir()
	}
	keyDir := fs.String("keys-dir", defKeyDir, "directory holding membrane.keys (the server's key dir) when the env keys are not set")
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
	fmt.Fprintf(stdout, "result=%s forwarded=%d paired=%d unpaired=%d\n", res.Result, res.Forwarded, res.Paired, res.Unpaired)
	if res.NoRaw > 0 || res.Unmembraned > 0 || res.Blocked > 0 {
		fmt.Fprintf(stdout, "no_raw=%d unmembraned=%d blocked=%d\n", res.NoRaw, res.Unmembraned, res.Blocked)
	}
	if res.Reason != "" {
		fmt.Fprintln(stdout, "reason: "+res.Reason)
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
	if res.LearnedLater > 0 {
		ids := make([]string, len(res.LearnedLaterIDs))
		for i, x := range res.LearnedLaterIDs {
			ids[i] = strconv.FormatInt(x, 10)
		}
		kinds := make([]string, 0, len(res.LearnedLaterKinds))
		for k, n := range res.LearnedLaterKinds {
			kinds = append(kinds, fmt.Sprintf("%s:%d", k, n))
		}
		sort.Strings(kinds)
		fmt.Fprintf(stdout, "learned_later_ids=%s kinds=%s\n", strings.Join(ids, ","), strings.Join(kinds, ","))
	}
	if !res.ChainOK {
		fmt.Fprintf(stdout, "chain_first_bad_id=%d\n", res.ChainFirstBadID)
	}
	if res.Result != membrane.VerifyPass || res.LearnedLater > 0 {
		fmt.Fprintln(stdout, "note: "+membrane.VerifyNote)
	}
	switch res.Result {
	case membrane.VerifyPass:
		return 0
	case membrane.VerifyInconclusive:
		return 3
	default:
		return 1
	}
}
