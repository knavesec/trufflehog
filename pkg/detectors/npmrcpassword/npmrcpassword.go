package npmrcpassword

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "npmrc_password"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From custom_regexRules.jsonl np.npmrc.3: npm .npmrc _password
// Pattern: (?://[^\s:\n]+)?:_password\s*=\s*([^\s\n;#]+)
var keyPat = regexp.MustCompile(`(?m)(?://[^\s:\n]+)?:_password\s*=\s*([^\s\n;#]+)`)

func (s Scanner) Keywords() []string {
	return []string{":_password", "_password=", ".npmrc"}
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
	return "Detects npm .npmrc _password. np.npmrc.3"
}
