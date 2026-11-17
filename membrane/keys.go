package membrane

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Environment variables holding the base64 32-byte membrane keys.
const (
	EnvEncKey  = "ARTEX_MEMBRANE_KEY"
	EnvHMACKey = "ARTEX_MEMBRANE_HMAC_KEY"
)

// KeysFileName is the key file created under the data dir when no env keys are set.
const KeysFileName = "membrane.keys"

// KeysSource reports where LoadKeysSource found the keys.
type KeysSource string

const (
	KeysEnv       KeysSource = "env"
	KeysFile      KeysSource = "file"
	KeysGenerated KeysSource = "generated"
)

type keysFile struct {
	Enc  string `json:"enc"`
	HMAC string `json:"hmac"`
}

// LoadKeys returns the AES-256 encryption key and the HMAC key: env vars
// first, then <dataDir>/membrane.keys (0600), generated if missing.
func LoadKeys(dataDir string) (encKey, hmacKey []byte, err error) {
	encKey, hmacKey, _, err = LoadKeysSource(dataDir)
	return encKey, hmacKey, err
}

// LoadKeysSource is LoadKeys that also reports where the keys came from.
// Setting only one of the two env vars is an error, as is a key file
// readable by group or others.
func LoadKeysSource(dataDir string) (encKey, hmacKey []byte, src KeysSource, err error) {
	e, h := strings.TrimSpace(os.Getenv(EnvEncKey)), strings.TrimSpace(os.Getenv(EnvHMACKey))
	switch {
	case e != "" && h != "":
		if encKey, err = decodeKey(EnvEncKey, e); err != nil {
			return nil, nil, "", err
		}
		if hmacKey, err = decodeKey(EnvHMACKey, h); err != nil {
			return nil, nil, "", err
		}
		return encKey, hmacKey, KeysEnv, nil
	case e != "" || h != "":
		return nil, nil, "", fmt.Errorf("membrane keys: %s and %s must both be set or both be absent", EnvEncKey, EnvHMACKey)
	}

	path := filepath.Join(dataDir, KeysFileName)
	encKey, hmacKey, err = readKeysFile(path)
	if err == nil {
		return encKey, hmacKey, KeysFile, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, "", err
	}
	encKey, hmacKey, err = generateKeysFile(path)
	if errors.Is(err, fs.ErrExist) { // another process won the race
		encKey, hmacKey, err = readKeysFile(path)
		return encKey, hmacKey, KeysFile, err
	}
	if err != nil {
		return nil, nil, "", err
	}
	return encKey, hmacKey, KeysGenerated, nil
}

func decodeKey(name, v string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("membrane keys: %s is not valid base64: %w", name, err)
	}
	if len(k) != 32 {
		return nil, fmt.Errorf("membrane keys: %s must decode to 32 bytes, got %d", name, len(k))
	}
	return k, nil
}

func readKeysFile(path string) ([]byte, []byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, nil, fmt.Errorf("membrane keys: %s has mode %v, want 0600", path, fi.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var kf keysFile
	if err := json.Unmarshal(raw, &kf); err != nil {
		return nil, nil, fmt.Errorf("membrane keys: parse %s: %w", path, err)
	}
	enc, err := decodeKey(path+" enc", kf.Enc)
	if err != nil {
		return nil, nil, err
	}
	mac, err := decodeKey(path+" hmac", kf.HMAC)
	if err != nil {
		return nil, nil, err
	}
	return enc, mac, nil
}

func generateKeysFile(path string) ([]byte, []byte, error) {
	enc, mac := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(enc); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(mac); err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, nil, fmt.Errorf("membrane keys: %w", err)
	}
	raw, _ := json.Marshal(keysFile{
		Enc:  base64.StdEncoding.EncodeToString(enc),
		HMAC: base64.StdEncoding.EncodeToString(mac),
	})
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, nil, err
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		f.Close()
		os.Remove(path)
		return nil, nil, fmt.Errorf("membrane keys: write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, nil, fmt.Errorf("membrane keys: write %s: %w", path, err)
	}
	return enc, mac, nil
}
