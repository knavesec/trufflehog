package custom_example

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "custom_example"

type Scanner struct{}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Adjust pattern and keywords for your rule. Use boundary characters to reduce false positives.
	keyPat = regexp.MustCompile(detectors.PrefixRegex([]string{"custom_example", "example_key"}) + `\b([A-Za-z0-9_-]{24,64})\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
func (s Scanner) Keywords() []string {
	return []string{"custom_example", "example_key"}
}

// FromData will find and optionally verify secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {
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

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Generic
}

func (s Scanner) Description() string {
	return "Custom example detector. Replace pattern and description for your rule."
}
