package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/offloadsecurity/offload-cli/internal/finding"
	"github.com/offloadsecurity/offload-cli/internal/scan"
	"github.com/offloadsecurity/offload-cli/internal/verdict"
)

// ANSI colors, disabled when not writing to a TTY / when NO_COLOR is set.
type palette struct{ reset, dim, red, mag, yel, blu, grn, bold string }

func colors(on bool) palette {
	if !on {
		return palette{}
	}
	return palette{
		reset: "\033[0m", dim: "\033[2m", bold: "\033[1m",
		red: "\033[31m", mag: "\033[35m", yel: "\033[33m",
		blu: "\033[34m", grn: "\033[32m",
	}
}

func sevColor(p palette, s finding.Severity) string {
	switch s {
	case finding.Critical:
		return p.mag
	case finding.High:
		return p.red
	case finding.Medium:
		return p.yel
	case finding.Low:
		return p.blu
	default:
		return p.dim
	}
}

// Table renders a human-readable report. color enables ANSI styling.
func Table(w io.Writer, rep scan.Report, color bool) {
	p := colors(color)

	fmt.Fprintf(w, "\n%sOffload scan%s  %s%s%s\n", p.bold, p.reset, p.dim, rep.Dir, p.reset)

	// Scanner status line — never hide a skipped/errored tool.
	for _, t := range rep.Tools {
		switch {
		case t.Skipped:
			fmt.Fprintf(w, "  %s- %-9s skipped%s (%s)\n", p.dim, t.Tool, p.reset, t.SkipHint)
		case t.Err != nil:
			fmt.Fprintf(w, "  %s! %-9s error%s: %s\n", p.yel, t.Tool, p.reset, firstLine(t.Err.Error()))
		default:
			noun := "finding(s)"
			if t.Tool == "syft" {
				noun = "component(s)"
			}
			fmt.Fprintf(w, "  %s✓ %-9s%s %d %s\n", p.grn, t.Tool, p.reset, t.Count, noun)
		}
	}

	if len(rep.Findings) == 0 && rep.Dismissed == 0 {
		fmt.Fprintf(w, "\n%s✓ No findings.%s\n\n", p.grn, p.reset)
		return
	}

	fmt.Fprintln(w)
	headed := false
	for _, f := range rep.Findings {
		c := sevColor(p, f.Severity)
		tag := ""
		if f.SecretVerdict != nil {
			if t := verdictTag(*f.SecretVerdict); t != "" {
				tag = " " + p.dim + t + p.reset
			}
		}
		if f.Dismissed() {
			if !headed {
				headed = true
				fmt.Fprintf(w, "\n%sDismissed as not secrets (heuristic verdicts; not counted toward --fail-on):%s\n", p.dim, p.reset)
			}
			c = p.dim
		}
		fmt.Fprintf(w, "%s%-8s%s %s%s%s%s\n", c, strings.ToUpper(string(f.Severity)), p.reset, p.bold, f.Title, p.reset, tag)
		loc := location(f)
		if loc != "" {
			fmt.Fprintf(w, "         %s%s%s\n", p.dim, loc, p.reset)
		}
		if f.FixVersion != "" {
			fmt.Fprintf(w, "         %sfix: %s%s\n", p.dim, f.FixVersion, p.reset)
		}
	}

	// Summary
	fmt.Fprintf(w, "\n%sSummary:%s ", p.bold, p.reset)
	parts := []string{}
	for _, s := range finding.Order {
		if n := rep.Counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s%d %s%s", sevColor(p, s), n, s, p.reset))
		}
	}
	counted := rep.Total() - rep.Dismissed
	switch {
	case len(parts) == 0:
		fmt.Fprintf(w, "%sno counted findings%s", p.grn, p.reset)
	case rep.Dismissed == 0:
		fmt.Fprintf(w, "%s  (%d total)", strings.Join(parts, "  "), counted)
	default:
		fmt.Fprintf(w, "%s  (%d counted)", strings.Join(parts, "  "), counted)
	}
	if rep.Dismissed > 0 {
		hidden := ""
		if rep.DismissedHidden {
			hidden = ", hidden"
		}
		fmt.Fprintf(w, "  %s%d dismissed as not secrets%s%s", p.dim, rep.Dismissed, hidden, p.reset)
	}
	fmt.Fprint(w, "\n\n")
}

// verdictTag is the short label shown next to a secret finding, e.g.
// "[not a secret: placeholder]". A likely_secret verdict gets no tag; a
// medium-confidence non-secret verdict is flagged for review, not dismissed.
func verdictTag(v verdict.Result) string {
	switch {
	case v.Dismissed():
		return "[" + strings.ToLower(v.Label) + ": " + v.Tag() + "]"
	case v.NonSecret():
		return "[review: " + v.Tag() + "]"
	}
	return ""
}

func location(f finding.Finding) string {
	switch f.Category {
	case finding.CategoryPackageVuln:
		if f.Package != "" {
			return fmt.Sprintf("%s@%s (%s)", f.Package, f.Version, f.Ecosystem)
		}
	default:
		if f.File != "" {
			if f.LineStart > 0 {
				return fmt.Sprintf("%s:%d", f.File, f.LineStart)
			}
			return f.File
		}
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
