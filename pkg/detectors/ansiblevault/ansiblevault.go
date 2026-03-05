package ansiblevault

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "ansible_vault"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From custom_regexRules.jsonl np.ansible.1: Ansible Vault (encrypted blob)
// Pattern: \$ANSIBLE_VAULT;[^;\n]+;[^;\n]+\s+([0-9a-f]{32,})
var keyPat = regexp.MustCompile(`\$ANSIBLE_VAULT;[^;\n]+;[^;\n]+\s+([0-9a-f]{32,})`)

func (s Scanner) Keywords() []string {
	return []string{"$ANSIBLE_VAULT", "ANSIBLE_VAULT"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	var results []detectors.Result
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		resMatch := strings.TrimSpace(match[1])
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Generic,
			DetectorName: detectorName,
			Raw:          []byte(resMatch),
		}
		if verify {
			fmt.Println("verification not implemented")
		}
		results = append(results, s1)
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType { return detectorspb.DetectorType_Generic }
func (s Scanner) Description() string {
	return "Detects Ansible Vault encrypted blobs. np.ansible.1"
}
