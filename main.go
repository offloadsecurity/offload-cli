// Command offload is a zero-dependency, open-source security scanner that
// orchestrates best-in-class tools (gitleaks, syft, grype, trivy) and emits a
// single, deduplicated finding stream as a table, JSON, or SARIF.
//
// It is the local, developer-facing edge of the Offload Security platform:
// the same detection engines, the same finding shape. Connect a repo to the
// platform to get org-wide correlation, attack paths, and compliance evidence.
package main

import (
	"os"

	"github.com/offloadsecurity/offload-cli/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
