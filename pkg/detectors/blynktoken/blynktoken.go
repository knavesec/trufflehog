package blynktoken

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "blynk_token"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl: Blynk device (32), org Bearer (40), oauth client id + secret
var keyPat1 = regexp.MustCompile(`(?i)https://(?:fra1\.|lon1\.|ny3\.|sgp1\.|blr1\.)*blynk\.cloud/external/api/[a-zA-Z0-9/]*\?token=\s*([a-zA-Z0-9_\-]{32})\s*&`)
var keyPat2 = regexp.MustCompile(`(?i)(?:Authorization:\s*Bearer\s*|\?token=)\s*([a-zA-Z0-9_\-]{40})\s*["\s\\]*https://(?:fra1\.|lon1\.|ny3\.|sgp1\.|blr1\.)*blynk\.cloud`)
var keyPat3 = regexp.MustCompile(`\b(oa2-client-id_[a-zA-Z0-9_\-]{32})\s*[:&]\s*([a-zA-Z0-9_\-]{40})`)

func (s Scanner) Keywords() []string {
	return []string{"blynk.cloud", "oa2-client-id_"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	seen := make(map[string]struct{})
	var results []detectors.Result
	for _, match := range keyPat1.FindAllStringSubmatch(dataStr, -1) {
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
	for _, match := range keyPat2.FindAllStringSubmatch(dataStr, -1) {
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
	for _, match := range keyPat3.FindAllStringSubmatch(dataStr, -1) {
		if len(match) < 3 {
			continue
		}
		// Report client_secret (second group)
		resMatch := strings.TrimSpace(match[2])
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
	return results, nil
}

func (s Scanner) Type() detectorspb.DetectorType { return detectorspb.DetectorType_Generic }
func (s Scanner) Description() string {
	return "Detects Blynk device/org/OAuth tokens. np.blynk.*"
}
