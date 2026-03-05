package vmwareviserver

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "vmware_viserver_credentials"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.vmware.1: Connect-VIServer ... -User x ... -Password y
var keyPat = regexp.MustCompile(`(?i)Connect-VIServer.{0,50}-User\s+(\S{3,30})\s+.{0,50}-Password\s+(\S{3,30})`)

func (s Scanner) Keywords() []string {
	return []string{"Connect-VIServer", "-User ", "-Password "}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	var results []detectors.Result
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		resMatch := strings.TrimSpace(match[2]) // password
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
	return "Detects Connect-VIServer -User/-Password credentials. np.vmware.1"
}
