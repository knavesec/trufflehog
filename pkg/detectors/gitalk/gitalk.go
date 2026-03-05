package gitalk

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "gitalk_oauth"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.gitalk.1: Gitalk OAuth clientID + clientSecret
var keyPat = regexp.MustCompile(`new\s+Gitalk\s*\(\s*\{\s*clientID:\s*'([a-f0-9]{20})',\s*clientSecret:\s*'([a-f0-9]{40})',`)

func (s Scanner) Keywords() []string {
	return []string{"Gitalk", "clientID", "clientSecret"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	var results []detectors.Result
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		// Report clientSecret as primary secret
		resMatch := strings.TrimSpace(match[2])
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
	return "Detects Gitalk OAuth credentials. np.gitalk.1"
}
