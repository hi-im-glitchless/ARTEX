package membrane

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenStoreWrongKeyIsKeyMismatch(t *testing.T) {
	s, p := newTestStore(t)
	if _, err := s.seedEnroll(KindPassword, "hunter2!", seedProv); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(p, bytes.Repeat([]byte{0x33}, 32), testHMACKey); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("wrong enc key: %v", err)
	}
	if _, err := OpenStore(p, testEncKey, bytes.Repeat([]byte{0x44}, 32)); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("wrong hmac key: %v", err)
	}
}

func TestKeysConfigured(t *testing.T) {
	t.Setenv(EnvEncKey, "")
	t.Setenv(EnvHMACKey, "")
	dir := t.TempDir()
	if KeysConfigured(dir) {
		t.Fatal("no env and no file: not configured")
	}
	t.Setenv(EnvEncKey, "x")
	if !KeysConfigured(dir) {
		t.Fatal("one env key set counts as configured (LoadKeys then reports the error)")
	}
	t.Setenv(EnvEncKey, "")
	if err := os.WriteFile(filepath.Join(dir, KeysFileName), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !KeysConfigured(dir) {
		t.Fatal("key file present: configured")
	}
}
