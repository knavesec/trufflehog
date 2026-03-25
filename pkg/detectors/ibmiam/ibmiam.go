package ibmiam

import (
	"context"
	"fmt"
	"net/http"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Same character class as Box (alphanumeric), length 44 for IBM IAM API keys.
	keyPat = regexp.MustCompile(`\b([0-9a-zA-Z_\-]{44})\b`)
)

// Keywords are used for efficiently pre-filtering chunks. IBM IAM API keys have no
// reliable substring to union-filter on, so none are registered (this detector is
// not scheduled via the keyword trie).
func (s Scanner) Keywords() []string {
	return []string{"ibm", "iam", "icr", "token"}
}

func (s Scanner) Description() string {
	return "IBM Cloud Identity and Access Management (IAM) API keys grant programmatic access to IBM Cloud resources. They are opaque alphanumeric strings used with IBM Cloud APIs."
}

// FromData will find and optionally verify IBM IAM API key secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	uniqueMatches := make(map[string]struct{})
	for _, match := range keyPat.FindAllStringSubmatch(dataStr, -1) {
		uniqueMatches[match[1]] = struct{}{}
	}

	for match := range uniqueMatches {
		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_IbmIam,
			Raw:          []byte(match),
		}

		if verify {
			client := s.client
			if client == nil {
				client = defaultClient
			}

			isVerified, extraData, verificationErr := verifyMatch(ctx, client, match)
			s1.Verified = isVerified
			s1.ExtraData = extraData
			s1.SetVerificationError(verificationErr, match)
		}

		results = append(results, s1)
	}

	return
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	_, _, _ = ctx, client, token
	fmt.Println("not implemented")
	return false, nil, nil
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_IbmIam
}
