package reactappenv

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "react_app_env_secret"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.reactapp.1: REACT_APP_*_USER = value, np.reactapp.2: REACT_APP_*_PASS = value
var keyPatUser = regexp.MustCompile(`(?i)REACT_APP(?:_[A-Z0-9]+)*_USER(?:NAME)?\s*=\s*['"]?([^\s'"$]{3,})(?:[\s'"$]|$)`)
var keyPatPass = regexp.MustCompile(`(?i)REACT_APP(?:_[A-Z0-9]+)*_PASS(?:WORD)?\s*=\s*['"]?([^\s'"$]{6,})(?:[\s'"$]|$)`)

func (s Scanner) Keywords() []string {
	return []string{"REACT_APP", "REACT_APP_"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	seen := make(map[string]struct{})
	var results []detectors.Result
	for _, re := range []*regexp.Regexp{keyPatUser, keyPatPass} {
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
	return "Detects REACT_APP_* user/password env vars. np.reactapp.1/.2"
}
