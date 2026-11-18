package cli

import (
	"flag"
	"fmt"
	"io"
)

// newFlagSet returns a flag set that reports parse errors without dumping the
// default Go usage (we print our own help).
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {}
	return fs
}

func usage(w io.Writer) {
	fmt.Fprint(w, `offload — open-source security scanner by Offload Security

USAGE:
  offload scan [path] [flags]     scan a directory (default ".")
  offload upload <results.json>   send a saved JSON report to the platform
  offload version                 print version
  offload help                    show this help

SCAN FLAGS:
  --format string     table | json | sarif           (default "table")
  --output string     write to a file instead of stdout
  --scanners string   comma list: secrets,sbom,sca,iac (default all)
  --fail-on string    exit 3 if a finding is >= this severity
                      (critical|high|medium|low)
  --sbom-components   include the SBOM component inventory as findings
  --no-color          disable ANSI colors
  --upload            send findings to the Offload platform (exit 4 if it
                      fails; a --fail-on hit still exits 3)

UPLOAD (scan --upload, or offload upload):
  OFFLOAD_URL / --platform-url   platform URL, e.g. https://offload.example.com
  OFFLOAD_API_KEY                CI/CD API key (env only, never a flag)
  OFFLOAD_CA_CERT                optional CA bundle for a private CA
  --repository, --branch, --default-branch, --commit
                                 override git / GitHub Actions detection

EXAMPLES:
  offload scan .
  offload scan ./repo --scanners secrets,iac
  offload scan . --format sarif --output offload.sarif
  offload scan . --fail-on high        # for CI

Scanners are optional external tools; a missing tool is reported as
"skipped", never silently treated as zero findings. Install what you need:
  gitleaks (secrets) · syft + grype (SBOM/SCA) · trivy (IaC)

Connect a repository to the Offload platform for org-wide correlation,
attack-path analysis, and compliance evidence: https://offloadsecurity.com
`)
}
