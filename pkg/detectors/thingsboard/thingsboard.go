package thingsboard

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "thingsboard_token"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.thingsboard.1: thingsboard.cloud/api/v1/ + 20 hex
// np.thingsboard.2: "provisionDeviceKey":" 20 hex, np.thingsboard.3: "provisionDeviceSecret":" 20 hex
var keyPat1 = regexp.MustCompile(`thingsboard\.cloud/api/v1/\s*([a-z0-9]{20})`)
var keyPat2 = regexp.MustCompile(`"provisionDeviceKey"\s*:\s*"\s*([a-z0-9]{20})\s*"`)
var keyPat3 = regexp.MustCompile(`"provisionDeviceSecret"\s*:\s*"\s*([a-z0-9]{20})\s*"`)

func (s Scanner) Keywords() []string {
	return []string{"thingsboard", "provisionDeviceKey", "provisionDeviceSecret"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	seen := make(map[string]struct{})
	var results []detectors.Result
	for _, re := range []*regexp.Regexp{keyPat1, keyPat2, keyPat3} {
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
	return "Detects ThingsBoard access token and provision keys. np.thingsboard.1/.2/.3"
}
