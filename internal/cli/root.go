// Package cli wires flags to the scan orchestrator and output formatters.
package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/offloadsecurity/offload-cli/internal/finding"
	"github.com/offloadsecurity/offload-cli/internal/output"
	"github.com/offloadsecurity/offload-cli/internal/scan"
)

// Version is stamped at build time via -ldflags "-X …cli.Version=vX.Y.Z".
var Version = "dev"

// Exit codes. 3 is the CI gate hit (chosen to not collide with Go's own 1/2).
const (
	exitOK      = 0
	exitError   = 1
	exitUsage   = 2
	exitGateHit = 3
)

// Run dispatches subcommands and returns a process exit code.
func Run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return exitUsage
	}
	switch args[0] {
	case "scan":
		return runScan(args[1:])
	case "version", "--version", "-v":
		fmt.Println("offload-cli " + Version)
		return exitOK
	case "help", "--help", "-h":
		usage(os.Stdout)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return exitUsage
	}
}

func runScan(args []string) int {
	fs := newFlagSet("scan")
	var (
		format    = fs.String("format", "table", "output format: table | json | sarif")
		outPath   = fs.String("output", "", "write output to a file instead of stdout")
		scanners  = fs.String("scanners", strings.Join(scan.AllScanners, ","), "comma-separated: secrets,sbom,sca,iac")
		failOn    = fs.String("fail-on", "", "exit non-zero if a finding is at or above this severity: critical|high|medium|low")
		sbomComps = fs.Bool("sbom-components", false, "include the SBOM component inventory as informational findings")
		noColor   = fs.Bool("no-color", false, "disable ANSI colors")
		noVerdict = fs.Bool("no-verdicts", false, "disable secret verdicts (raw gitleaks behaviour)")
		hideDism  = fs.Bool("hide-dismissed", false, "leave findings dismissed as not secrets out of the output (still counted in the summary)")
	)
	// Go's flag package stops at the first positional, so `scan . --format json`
	// would drop the flags. Reorder so all flags precede the path.
	if err := fs.Parse(reorder(args)); err != nil {
		return exitUsage
	}

	dir := "."
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "error: %q is not a directory\n", dir)
		return exitUsage
	}

	enabled, err := parseScanners(*scanners)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitUsage
	}

	var gate finding.Severity
	if *failOn != "" {
		gate = finding.NormalizeSeverity(*failOn)
	}

	rep := scan.Run(context.Background(), scan.Options{
		Dir:                   dir,
		Enabled:               enabled,
		IncludeSBOMComponents: *sbomComps,
		NoVerdicts:            *noVerdict,
	})
	if *hideDism {
		rep.HideDismissed()
	}

	w := os.Stdout
	if *outPath != "" {
		f, err := os.Create(*outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot write %s: %v\n", *outPath, err)
			return exitError
		}
		defer f.Close()
		w = f
	}

	switch *format {
	case "table":
		output.Table(w, rep, colorEnabled(*noColor, w == os.Stdout))
	case "json":
		if err := output.JSON(w, rep, Version); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return exitError
		}
	case "sarif":
		if err := output.SARIF(w, rep, Version); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return exitError
		}
	default:
		fmt.Fprintf(os.Stderr, "error: unknown format %q (use table|json|sarif)\n", *format)
		return exitUsage
	}

	// CI gate. Counts exclude findings a secret verdict dismissed.
	if s, hit := gateHit(rep, gate); hit {
		fmt.Fprintf(os.Stderr, "\nfail-on: found %s findings at or above %q — failing.\n", string(s), string(gate))
		return exitGateHit
	}
	return exitOK
}

// gateHit reports the most severe counted severity at or above gate.
// Dismissed findings are not in rep.Counts, so they never trip the gate.
func gateHit(rep scan.Report, gate finding.Severity) (finding.Severity, bool) {
	if gate == "" {
		return "", false
	}
	for _, s := range finding.Order {
		if rep.Counts[s] > 0 && s.AtLeast(gate) {
			return s, true
		}
	}
	return "", false
}

// boolScanFlags are the scan flags that take no value; used by reorder to know
// whether the next token is a value or a positional.
var boolScanFlags = map[string]bool{"sbom-components": true, "no-color": true,
	"no-verdicts": true, "hide-dismissed": true}

// reorder moves flags ahead of positional args so stdlib flag parsing (which
// stops at the first non-flag) sees every flag regardless of where the user
// put the path. Supports `--flag value`, `--flag=value`, and bool flags.
func reorder(args []string) []string {
	var flags, pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" { // everything after is positional
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(a, "=") && !boolScanFlags[name] && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			pos = append(pos, a)
		}
	}
	return append(flags, pos...)
}

func parseScanners(csv string) (map[string]bool, error) {
	valid := map[string]bool{}
	for _, s := range scan.AllScanners {
		valid[s] = true
	}
	enabled := map[string]bool{}
	for _, part := range strings.Split(csv, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if p == "all" {
			for _, s := range scan.AllScanners {
				enabled[s] = true
			}
			continue
		}
		if !valid[p] {
			return nil, fmt.Errorf("unknown scanner %q (valid: %s)", p, strings.Join(scan.AllScanners, ", "))
		}
		enabled[p] = true
	}
	if len(enabled) == 0 {
		return nil, fmt.Errorf("no scanners selected")
	}
	return enabled, nil
}

func colorEnabled(noColor, isStdout bool) bool {
	if noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	return isStdout
}
