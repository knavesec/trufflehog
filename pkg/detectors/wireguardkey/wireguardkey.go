package wireguardkey

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "wireguard_key"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.wireguard.1: PrivateKey = base64, np.wireguard.2: PresharedKey = base64
var keyPat1 = regexp.MustCompile(`PrivateKey\s*=\s*([A-Za-z0-9+/]{43}=)`)
var keyPat2 = regexp.MustCompile(`PresharedKey\s*=\s*([A-Za-z0-9+/]{43}=)`)

func (s Scanner) Keywords() []string {
	return []string{"PrivateKey", "PresharedKey", "WireGuard"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	seen := make(map[string]struct{})
	var results []detectors.Result
	for _, re := range []*regexp.Regexp{keyPat1, keyPat2} {
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
	return "Detects WireGuard PrivateKey and PresharedKey. np.wireguard.1/.2"
}
