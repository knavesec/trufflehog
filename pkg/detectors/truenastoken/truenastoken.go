package truenastoken

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "truenas_api_key"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.truenas.1: "params":[" digits-64alnum ], np.truenas.2: Bearer digits-64alnum
var keyPat1 = regexp.MustCompile(`"params"\s*:\s*\[\s*"\s*(\d+-[a-zA-Z0-9]{64})\s*"\s*\]`)
var keyPat2 = regexp.MustCompile(`Bearer\s*(\d+-[a-zA-Z0-9]{64})\b`)

func (s Scanner) Keywords() []string {
	return []string{"params", "Bearer", "truenas"}
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
	return "Detects TrueNAS API key. np.truenas.1/.2"
}
