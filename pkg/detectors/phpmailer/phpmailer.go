package phpmailer

import (
	"context"
	"fmt"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const detectorName = "phpmailer_credentials"

type Scanner struct{}

var _ detectors.Detector = (*Scanner)(nil)

// From regexRules.jsonl np.phpmailer.1: $mail->Host, ->Username, ->Password
var keyPat = regexp.MustCompile(`\$mail->Host\s*=\s*'([^'\n]{5,})';.*?\$mail->Username\s*=\s*'([^'\n]{5,})';.*?\$mail->Password\s*=\s*'([^'\n]{5,})'`)

func (s Scanner) Keywords() []string {
	return []string{"$mail->", "->Password", "->Username", "->Host"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	dataStr := string(data)
	matches := keyPat.FindAllStringSubmatch(dataStr, -1)
	var results []detectors.Result
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		resMatch := strings.TrimSpace(match[3]) // password
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
	return "Detects PHPMailer Host/Username/Password. np.phpmailer.1"
}
