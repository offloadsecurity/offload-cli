package scanners

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/offloadsecurity/offload-cli/internal/finding"
)

// SBOMBinary is the tool this scanner wraps.
const SBOMBinary = "syft"

// cyclonedx is the minimal slice of a CycloneDX-JSON SBOM we read.
type cyclonedx struct {
	Components []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
		Type    string `json:"type"`
	} `json:"components"`
}

// SBOM generates a CycloneDX SBOM for a directory with syft and writes it to
// sbomPath (for the SCA stage to consume). Command mirrors the platform:
//
//	syft dir:<dir> -o cyclonedx-json=<out> -q
//
// It returns the parsed component list (as informational SBOM findings when
// includeComponents is set) plus the on-disk SBOM path.
func SBOM(ctx context.Context, dir, sbomPath string, includeComponents bool) ([]finding.Finding, Result) {
	res := Result{Tool: SBOMBinary}
	if _, ok := available(SBOMBinary); !ok {
		res.Skipped = true
		res.SkipHint = "install syft: https://github.com/anchore/syft#installation"
		return nil, res
	}

	_, err := run(ctx, 8*time.Minute, SBOMBinary,
		"dir:"+dir, "-o", "cyclonedx-json="+sbomPath, "-q")
	if err != nil {
		res.Err = err
		return nil, res
	}

	raw, err := os.ReadFile(sbomPath)
	if err != nil {
		res.Err = err
		return nil, res
	}
	var doc cyclonedx
	if err := json.Unmarshal(raw, &doc); err != nil {
		res.Err = err
		return nil, res
	}
	res.Count = len(doc.Components)

	if !includeComponents {
		return nil, res
	}
	findings := make([]finding.Finding, 0, len(doc.Components))
	for _, c := range doc.Components {
		if c.Name == "" {
			continue
		}
		findings = append(findings, finding.New(finding.Finding{
			Category:          finding.CategorySBOM,
			Severity:          finding.Info,
			Title:             c.Name + " " + c.Version,
			PrimaryIdentifier: c.PURL,
			Package:           c.Name,
			Version:           c.Version,
			PURL:              c.PURL,
			Ecosystem:         c.Type,
			Tool:              SBOMBinary,
		}))
	}
	return findings, res
}

// DefaultSBOMPath returns a temp path for the intermediate SBOM.
func DefaultSBOMPath() string {
	return filepath.Join(os.TempDir(), "offload-sbom.cdx.json")
}
