# offload-cli

**One command to scan a repo for secrets, vulnerable dependencies, and IaC misconfigurations.** Open source, zero-dependency Go binary, SARIF-native.

`offload-cli` is the local, developer-facing edge of the [Offload Security](https://offloadsecurity.com) platform — the same detection engines, the same unified finding shape. Run it in your terminal or CI; connect a repo to the platform when you want org-wide correlation, attack-path analysis, and compliance evidence.

```
$ offload scan .

Offload scan  .
  ✓ gitleaks  2 finding(s)
  ✓ grype     10 finding(s)
  ✓ syft      2 component(s)
  ✓ trivy     3 finding(s)

CRITICAL  GHSA-jf85-cpcp-j695 in lodash
          lodash@4.17.4 (npm)
          fix: 4.17.12
CRITICAL  Uncovered a GitHub Personal Access Token…
          config.py:1
HIGH      Security groups should not allow unrestricted ingress…
          main.tf:6

Summary: 2 critical  6 high  5 medium  2 low  (15 total)
```

## What it does

| Scanner | Wraps | Finds |
|---|---|---|
| `secrets` | [gitleaks](https://github.com/gitleaks/gitleaks) | hardcoded secrets & tokens (redacted in output) |
| `sbom` | [syft](https://github.com/anchore/syft) | a CycloneDX software bill of materials |
| `sca` | [grype](https://github.com/anchore/grype) | known-vulnerable dependencies, with fix versions |
| `iac` | [trivy](https://trivy.dev) | Terraform / Kubernetes / CloudFormation / Dockerfile misconfigurations |

Results from every tool are **deduplicated by a scanner-independent fingerprint** and merged into one severity-ranked stream — so the same issue found by two tools shows up once. Output as a **table**, **JSON**, or **SARIF 2.1.0** for GitHub code scanning.

## Secret verdicts

A secrets pattern that matches `password` also matches `password = login_data.password` or `--password="${DB_PASS}"`, neither of which puts a credential in source. `offload scan` classifies every gitleaks finding before redacting it and attaches a **verdict** (`likely_secret`, `likely_false_positive` or `not_a_secret`), a **confidence**, the **signals** that fired and a one-line **reason**:

```
HIGH     Detected a Generic API Key…
         app/settings.py:2

Dismissed as not secrets (heuristic verdicts; not counted toward --fail-on):
CRITICAL Uncovered a GitHub Personal Access Token… [likely false positive: fails token checksum]
         app/client.ts:1
HIGH     Detected a Generic API Key… [not a secret: runtime value]
         app/client.ts:2

Summary: 1 high  (1 counted)  2 dismissed as not secrets
```

- Only a **high-confidence** non-secret verdict dismisses a finding: placeholders, env/secret-store references, runtime expressions, code handling a variable, hashed values, GitHub/npm tokens that fail their built-in checksum. A hardcoded literal that merely looks weak (`password = "admin"`) stays a secret.
- Dismissed findings are **kept**: listed after the real ones, counted in the summary, and excluded from `--fail-on`. JSON carries the verdict as `secret_verdict` (with `summary.dismissed`); SARIF carries it in `properties.secretVerdict` and reports dismissed results at level `note`.
- `--hide-dismissed` leaves them out of the output (the summary still counts them); `--no-verdicts` restores raw gitleaks behaviour.
- Verdicts are **heuristics**, not proof: always check the reason. Reasons mask the matched value rather than quote it. gitleaks' own allowlists already drop many placeholders, so verdicts mostly act on what gets past them.

## Install

`offload-cli` orchestrates external scanner binaries — install the ones you want; a missing tool is reported as **skipped**, never silently treated as zero findings.

```bash
# the CLI (Go 1.21+)
go install github.com/offloadsecurity/offload-cli@latest
# → installs the `offload-cli` binary; alias or rename to `offload` if you like

# the scanners it drives (install what you need)
brew install gitleaks syft grype trivy      # macOS
```

Or download a prebuilt binary from [Releases](https://github.com/offloadsecurity/offload-cli/releases).

## Usage

```bash
offload scan .                                  # scan the current dir, all scanners
offload scan ./service --scanners secrets,iac   # only some scanners
offload scan . --format sarif --output offload.sarif
offload scan . --fail-on high                   # exit 3 if any finding ≥ high (for CI)
```

| Flag | Description | Default |
|---|---|---|
| `--format` | `table` \| `json` \| `sarif` | `table` |
| `--output` | write to a file instead of stdout | stdout |
| `--scanners` | comma list: `secrets,sbom,sca,iac` | all |
| `--fail-on` | exit `3` if a finding is ≥ this severity (`critical`\|`high`\|`medium`\|`low`) | never fail |
| `--sbom-components` | include the SBOM component inventory as findings | off |
| `--no-color` | disable ANSI colors | off |

**Exit codes:** `0` success · `2` usage error · `3` `--fail-on` threshold hit.

## GitHub Action

```yaml
# .github/workflows/security.yml
name: Security
on: [push, pull_request]
jobs:
  offload:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: "1.21" }
      - uses: offloadsecurity/offload-cli@v0.1.3
        with:
          path: .
          fail-on: high
          sarif-file: offload.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: offload.sarif
```

## The finding model

Every finding carries a stable `finding_fingerprint` (SHA-256 over category + identity, **excluding** tool, severity, and line numbers; secrets are the one exception and include their position, so two short secrets whose redacted snippets match are never merged), a canonical lowercase `severity` (`critical`→`info`), and the software component or file it belongs to. This is the same shape the Offload platform uses, so local results line up with what you see once a repo is connected.

## From local scan to a governed program

`offload-cli` gives you the detection edge for free. The [Offload platform](https://offloadsecurity.com) adds what a single scan can't: deduplicated risk across every repo and cloud account, identity-aware attack paths to crown-jewel assets, and compliance evidence mapped to frameworks — SaaS or fully on-premises.

## Built on

offload-cli stands on excellent open-source tools, which it runs as external
programs (it does not embed or redistribute them):
[syft](https://github.com/anchore/syft) & [grype](https://github.com/anchore/grype)
(Apache-2.0, © Anchore), [trivy](https://github.com/aquasecurity/trivy)
(Apache-2.0, © Aqua Security), and [gitleaks](https://github.com/gitleaks/gitleaks)
(MIT). offload-cli is not affiliated with or endorsed by these projects; names
are used only to describe what it wraps. See [NOTICE](NOTICE).

## License

[Apache License 2.0](LICENSE). Contributions welcome.
