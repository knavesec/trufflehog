package httpbasicauth

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "http_basic_auth"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.http.1: Authorization Basic <base64>
var keyPat = regexp.MustCompile(`(?i)Authorization\s*(?::\s*|\s*.{1,5}\s*)Basic\s+([A-Za-z0-9+/]{6,}={0,2})(?:[^A-Za-z0-9+/=]|$)`)

func (s Scanner) Keywords() []string {
	return []string{"Authorization", "Basic "}
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
	return "Detects HTTP Basic Authentication. np.http.1"
}
