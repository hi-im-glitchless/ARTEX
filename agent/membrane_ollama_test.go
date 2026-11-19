package agent

import (
	"errors"
	"testing"
)

// Port: an Ollama profile without a base URL dials the local default, so it
// is a trusted local endpoint (no membrane) and builds without an engine;
// with a remote base URL it still needs the membrane.
func TestOllamaDefaultBaseURLIsLocal(t *testing.T) {
	t.Setenv(MembraneEnv, "")
	c := Config{Format: FormatOllama, Model: "llama3"}
	if c.MembraneRequired() {
		t.Fatal("Ollama with the default base URL must not require the membrane")
	}
	if _, err := c.NewProvider(); err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	c.BaseURL = "https://ollama.example.net/v1"
	if !c.MembraneRequired() {
		t.Fatal("a remote Ollama gateway must require the membrane")
	}
	if _, err := c.NewProvider(); !errors.Is(err, ErrMembraneNotInitialised) {
		t.Fatalf("NewProvider = %v, want ErrMembraneNotInitialised", err)
	}
}
