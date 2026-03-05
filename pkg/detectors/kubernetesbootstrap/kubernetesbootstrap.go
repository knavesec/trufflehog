package kubernetesbootstrap

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "kubernetes_bootstrap_token"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.kubernetes.1: token/Token/TOKEN/bootstrap context then 6hex.16hex
// np.kubernetes.2: token-id: 6hex, token-secret: 16hex
var keyPat1 = regexp.MustCompile(`(?i)(?:token|bootstrap).{0,8}\b([a-z0-9]{6}\.[a-z0-9]{16})\b`)
var keyPat2 = regexp.MustCompile(`token-id:\s+([a-z0-9]{6})\s+token-secret:\s+([a-z0-9]{16})\b`)

func (s Scanner) Keywords() []string {
	return []string{"token-id", "token-secret", "bootstrap"}
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
		if len(match) < 3 {
			continue
		}
		resMatch := strings.TrimSpace(match[1]) + "." + strings.TrimSpace(match[2])
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
	return "Detects Kubernetes bootstrap token. np.kubernetes.1/.2"
}
