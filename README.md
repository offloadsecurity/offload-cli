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
      - uses: offloadsecurity/offload-cli@main
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

Every finding carries a stable `finding_fingerprint` (SHA-256 over category + identity, **excluding** tool, severity, and line numbers), a canonical lowercase `severity` (`critical`→`info`), and the software component or file it belongs to. This is the same shape the Offload platform uses, so local results line up with what you see once a repo is connected.

## From local scan to a governed program

`offload-cli` gives you the detection edge for free. The [Offload platform](https://offloadsecurity.com) adds what a single scan can't: deduplicated risk across every repo and cloud account, identity-aware attack paths to crown-jewel assets, and compliance evidence mapped to frameworks — SaaS or fully on-premises.

## License

[Apache License 2.0](LICENSE). Contributions welcome.
