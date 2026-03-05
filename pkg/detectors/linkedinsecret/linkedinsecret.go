package linkedinsecret

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "linkedin_oauth"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.linkedin.1: LinkedIn Client ID (12-14 chars), np.linkedin.2: LinkedIn Secret (16 chars)
var keyPatID = regexp.MustCompile(`(?i)linkedin.?(\s*(?:api|app|application|client|consumer|customer)\s*)?.?(\s*(?:id|identifier|key)\s*).{0,2}\s{0,20}.{0,2}\s{0,20}\b([a-z0-9]{12,14})\b`)
var keyPatSecret = regexp.MustCompile(`(?i)linkedin.?(\s*(?:api|app|application|client|consumer|customer|secret|key)\s*).?(\s*(?:key|oauth|sec|secret)\s*).{0,2}\s{0,20}.{0,2}\s{0,20}\b([a-z0-9]{16})\b`)

func (s Scanner) Keywords() []string {
	return []string{"linkedin"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	seen := make(map[string]struct{})
	var results []detectors.Result
	for _, re := range []*regexp.Regexp{keyPatID, keyPatSecret} {
		for _, match := range re.FindAllStringSubmatch(dataStr, -1) {
			if len(match) < 4 {
				continue
			}
			resMatch := strings.TrimSpace(match[len(match)-1])
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
	return "Detects LinkedIn client ID and secret. np.linkedin.1/.2"
}
