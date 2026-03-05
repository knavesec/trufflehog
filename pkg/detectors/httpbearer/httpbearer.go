package httpbearer

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "http_bearer_token"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.http.2: Authorization Bearer <token>
var keyPat = regexp.MustCompile(`(?i)Authorization\s*(?::\s*|\s*.{1,5}\s*)Bearer\s+([a-zA-Z0-9._~+/=-]{6,})(?:[^a-zA-Z0-9._~+/=-]|$)`)

func (s Scanner) Keywords() []string {
	return []string{"Authorization", "Bearer "}
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
	return "Detects HTTP Bearer token. np.http.2"
}
