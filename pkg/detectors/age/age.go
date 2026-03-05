package age

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "age_encryption"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.age.1: Age Recipient (X25519 public key)
// np.age.2: Age Identity (secret key)
var keyPatRecipient = regexp.MustCompile(`\b(age1[0-9a-z]{58})\b`)
var keyPatSecret = regexp.MustCompile(`\b(AGE-SECRET-KEY-1[0-9A-Z]{58})\b`)

func (s Scanner) Keywords() []string {
	return []string{"age1", "AGE-SECRET-KEY-1"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	seen := make(map[string]struct{})
	var results []detectors.Result
	for _, re := range []*regexp.Regexp{keyPatRecipient, keyPatSecret} {
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
	return "Detects Age encryption keys (recipient and secret). np.age.1/.2"
}
