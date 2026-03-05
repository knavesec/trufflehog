# Custom detector rules

Custom rules follow the same structure as standard detectors but:

- **No test files**: Do not add `rulename_test.go` or `rulename_integration_test.go`.
- **Verification**: In the `if verify { ... }` block, do not implement real verification; use `fmt.Println("verification not implemented")` only.
- **Type**: Use `detectorspb.DetectorType_Generic` and set `Result.DetectorName` to a unique name for the rule (e.g. the package/detector name).

## Structure (copy from `custom_example` or `custom_rule_template`)

1. **Package**: One directory per rule, e.g. `pkg/detectors/my_rule/my_rule.go`.
2. **Scanner**: `type Scanner struct{}` implementing `detectors.Detector`.
3. **Pattern**: `keyPat` (or similar) using `regexp.MustCompile`; prefer `detectors.PrefixRegex([]string{"keyword"}) + \`\b(capture)\b\`` to reduce false positives.
4. **Keywords()**: Return strings used for pre-filtering chunks (include secret prefix or service name).
5. **FromData()**: Parse data, collect matches, build `detectors.Result` with `DetectorType: detectorspb.DetectorType_Generic`, `DetectorName: "my_rule"`, and `Raw`. In `if verify { fmt.Println("verification not implemented") }`.
6. **Type()**: Return `detectorspb.DetectorType_Generic`.
7. **Description()**: Return a short description of what the rule detects.

## Registering a new custom rule

Add the detector to `pkg/engine/defaults/defaults.go`:

1. Add import: `"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/my_rule"`.
2. In `buildDetectorList()`, append `&my_rule.Scanner{}` (e.g. in the "Custom rules" section).
