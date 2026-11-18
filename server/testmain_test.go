package server

import (
	"database/sql"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/membrane"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// Pinned membrane keys for the server test database (base64 of 32 bytes).
var (
	testMembraneEncKey  = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("e", 32)))
	testMembraneHMACKey = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("h", 32)))
)

// TestMain acquires a PostgreSQL advisory lock (7337741002) for the entire
// server test suite so cross-package DELETE cleanup races with db/agent
// packages are avoided when running `go test ./...`.
func TestMain(m *testing.M) {
	// Own database per package (#80): with separate databases, packages stop
	// contending on shared tables and the advisory lock below stops
	// serializing go test ./... across packages.
	db.SuffixTestDatabase("server")
	// Every server test opens the same membrane table: pin its keys so no
	// test generates its own and finds rows it cannot decrypt.
	os.Setenv(membrane.EnvEncKey, testMembraneEncKey)   //nolint:errcheck
	os.Setenv(membrane.EnvHMACKey, testMembraneHMACKey) //nolint:errcheck
	dsn, _, err := db.DSN()
	if err != nil {
		os.Exit(m.Run())
	}
	conn, err := sql.Open("pgx", dsn)
	if err != nil || conn.Ping() != nil {
		os.Exit(m.Run())
	}
	defer conn.Close()
	if _, err := conn.Exec(`SELECT pg_advisory_lock(7337741002)`); err != nil {
		os.Exit(m.Run())
	}
	defer conn.Exec(`SELECT pg_advisory_unlock(7337741002)`) //nolint:errcheck
	os.Exit(m.Run())
}
