package gradlecredentials

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "gradle_credentials"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.gradle.1: Hardcoded Gradle credentials { username 'x' password 'y' }
var keyPat = regexp.MustCompile(`(?is)credentials\s*\{\s*(?:\s*//.*)*\s*(?:username|password)\s+['"]([^'"]{1,60})['"]\s*(?:\s*//.*)*\s*(?:username|password)\s+['"]([^'"]{1,60})['"]`)

func (s Scanner) Keywords() []string {
	return []string{"credentials ", "credentials {", "gradle"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	var results []detectors.Result
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		// Report both; use password (second capture) as primary
		resMatch := strings.TrimSpace(match[2])
		if resMatch == "" {
			resMatch = strings.TrimSpace(match[1])
		}
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
	return "Detects hardcoded Gradle credentials. np.gradle.1"
}
