package odbcconnection

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "odbc_connection_string"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.odbc.1: User/UserId/Uid = x; ... Password/Pwd = y
var keyPat = regexp.MustCompile(`(?i)(?:User\s+Id|UserId|Uid|User)\s*=\s*([^\s;]{3,100})\s*;.{0,10}(?:Password|Pwd)\s*=\s*([^\t;]{3,100})\s*(?:[;"']|$)`)

func (s Scanner) Keywords() []string {
	return []string{"Password", "Pwd", "User ", "UserId", "ODBC"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	var results []detectors.Result
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
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
	return "Detects ODBC connection string credentials. np.odbc.1"
}
