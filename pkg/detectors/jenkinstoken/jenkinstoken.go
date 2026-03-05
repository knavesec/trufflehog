package jenkinstoken

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "jenkins_token"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.jenkins.1: Jenkins token or crumb (32-36 hex or UUID)
// np.jenkins.2: Jenkins setup admin password
var keyPat1 = regexp.MustCompile(`(?i)jenkins.{0,12}(?:\s*(?:crumb|token).{0,10})?\s*([0-9a-f]{32,36}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?:[^0-9a-f-]|$)`)
var keyPat2 = regexp.MustCompile(`(?m)Please\s+use\s+the\s+following\s+password\s+to\s+proceed\s+to\s+installation:\s*(?:\n\n|\r\n\r\n)([a-f0-9]{30,36})\s*$`)

func (s Scanner) Keywords() []string {
	return []string{"jenkins", "crumb", "token"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	seen := make(map[string]struct{})
	var results []detectors.Result
	for _, re := range []*regexp.Regexp{keyPat1, keyPat2} {
		for _, match := range re.FindAllStringSubmatch(dataStr, -1) {
			if len(match) < 2 {
				continue
			}
			resMatch := strings.TrimSpace(match[1])
			if _, ok := seen[resMatch]; ok {
				continue
			}
			seen[resMatch] = struct{}{}
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
	}
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType { return detectorspb.DetectorType_Generic }
func (s Scanner) Description() string {
	return "Detects Jenkins token/crumb and setup admin password. np.jenkins.1/.2"
}
