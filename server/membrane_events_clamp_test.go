package server

import (
	"encoding/json"
	"testing"
)

// Final review extra: a page size above the maximum is clamped to the
// maximum (500), not silently reset to the default (50).
func TestMembraneEventsPageSizeClamp(t *testing.T) {
	f := newSeedFixture(t)
	for q, want := range map[string]int{"size=1000": 500, "size=500": 500, "size=0": 50, "size=7": 7} {
		w := membraneAPICall(t, f.s, "GET", "/api/tasks/"+f.id()+"/membrane/events?"+q, nil)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", q, w.Code, w.Body)
		}
		var out struct {
			Size int `json:"size"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Size != want {
			t.Errorf("%s: size %d, want %d", q, out.Size, want)
		}
	}
}
