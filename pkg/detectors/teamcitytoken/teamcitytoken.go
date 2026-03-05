package teamcitytoken

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "teamcity_api_token"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.teamcity.1: JWT-like eyJ0eXAiOiAiVENWMiJ9.xxx.xxx
var keyPat = regexp.MustCompile(`\b(eyJ0eXAiOiAiVENWMiJ9\.[A-Za-z0-9_-]{36}\.[A-Za-z0-9_-]{48})(?:[^A-Za-z0-9_-]|$)`)

func (s Scanner) Keywords() []string {
	return []string{"eyJ0eXAiOiAiVENWMiJ9", "TCV2", "teamcity"}
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
	return "Detects TeamCity API token. np.teamcity.1"
}
