package membrane

import (
	"slices"
	"testing"
)

func TestBrandVariants(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"Acme Bank", []string{"Acme Bank", "AcmeBank", "acme-bank", "acmebank"}},
		{"acmebank.pt", []string{"acmebank"}},
		{"ACMEBANK.co.uk", []string{"acmebank"}},
		{"  Acme   Bank  ", []string{"Acme Bank", "AcmeBank", "acme-bank", "acmebank"}},
		{"Acme-Bank", []string{"Acme-Bank", "AcmeBank", "acme-bank", "acmebank"}},
		{"Acme", []string{"Acme", "acme"}},
		{"acme", []string{"acme"}},
		{"Big Co", []string{"Big Co", "BigCo", "big-co", "bigco"}},
		{"IBM", nil},    // shorter than 4: dropped
		{"abc.pt", nil}, // root label shorter than 4
		{"A B", nil},    // every variant shorter than 4
		{"", nil},
		{"pt", nil}, // bare public suffix
	}
	for _, c := range cases {
		got := BrandVariants(c.in)
		if !slices.Equal(got, c.want) {
			t.Errorf("BrandVariants(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
