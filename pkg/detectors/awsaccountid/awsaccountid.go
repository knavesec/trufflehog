package awsaccountid

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "aws_account_id"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.aws.3: aws_account_id = 12 digits (optional hyphens)
var keyPat = regexp.MustCompile("(?i)aws_?(?:account)_?(?:id)?[\"'`]?\\s{0,30}(?::|=>|=)\\s{0,30}[\"'`]?([0-9]{4}-?[0-9]{4}-?[0-9]{4})")

func (s Scanner) Keywords() []string {
	return []string{"aws_account", "account_id", "aws "}
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
	return "Detects AWS account ID. np.aws.3"
}
