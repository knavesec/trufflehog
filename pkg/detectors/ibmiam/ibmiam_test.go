package ibmiam

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestIbmIam_KeywordsEmpty(t *testing.T) {
	d := Scanner{}
	if kw := d.Keywords(); len(kw) != 0 {
		t.Fatalf("Keywords() should be empty for prefilter; got %v", kw)
	}
}

func TestIbmIam_Pattern(t *testing.T) {
	d := Scanner{}
	const validKey = "Abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH" // 44 alphanumeric
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "valid pattern",
			input: `
				[DEBUG] using key=` + validKey + `
			`,
			want: []string{validKey},
		},
		{
			name: "invalid pattern - wrong length",
			input: `
				[DEBUG] key=Abcdefghijklmnopqrstuvwxyz0123456789ABC
			`,
			want: nil,
		},
		{
			name: "invalid pattern - non alphanumeric",
			input: `
				[DEBUG] key=Abcdefghijklmnopqrstuvwxyz0123456789ABCD-EFGH
			`,
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results, err := d.FromData(context.Background(), false, []byte(test.input))
			require.NoError(t, err)

			if len(results) != len(test.want) {
				t.Errorf("mismatch in result count: expected %d, got %d", len(test.want), len(results))
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}

			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}
