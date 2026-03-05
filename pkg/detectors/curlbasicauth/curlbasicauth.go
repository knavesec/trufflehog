package curlbasicauth

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "curl_basic_auth"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From custom_regexRules.jsonl np.curl.1/.2/.3: curl -u user:password
var keyPat1 = regexp.MustCompile(`curl\s+-u\s+[^:\s]+:'([^']*)'`)
var keyPat2 = regexp.MustCompile(`curl\s+-u\s+[^:\s]+:"([^"]*)"`)
var keyPat3 = regexp.MustCompile(`curl\s+-u\s+[^:\s]+:([^\s]+)`)

func (s Scanner) Keywords() []string {
	return []string{"curl ", "curl -u", "curl -u "}
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
	return "Detects curl -u basic auth password. np.curl.1/.2/.3"
}
