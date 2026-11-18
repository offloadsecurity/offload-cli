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

**Exit codes:** `0` success · `2` usage error · `3` `--fail-on` threshold hit · `4` upload failed (see below).

## Send results to Offload

`--upload` sends the findings to your Offload Security platform through its SARIF import (`POST /api/cicd/sarif/upload`), so they show up in **Code Command Center → SARIF Imports** next to your other code findings.

1. In the platform, open your profile menu → **API Keys** → **Create API Key**, and pick the **CI/CD Pipeline** scope preset (it includes the `scans:trigger` scope the upload needs). The key's owner also needs the Run Scans permission.
2. Run:

```bash
export OFFLOAD_URL=https://offload.example.com
export OFFLOAD_API_KEY=osk_...            # from a CI secret; never passed as a flag
offload scan . --upload --fail-on high

offload scan . --format json --output results.json
offload upload results.json               # or send a saved JSON report later
```

- The repository, branch and commit are read from GitHub Actions' environment or from `git` (`remote get-url origin`, the current branch, `HEAD`); override them with `--repository`, `--branch`, `--default-branch` and `--commit`.
- Each scanner is sent as its own run. When the branch is known, the upload is a full run, so findings that scanner no longer reports on that branch are resolved on the platform. A **skipped** scanner is not sent, so nothing is resolved on its behalf. If the branch is unknown, the upload is partial and nothing is resolved; the CLI prints a warning when this happens.
- Secrets are sent as the rule, file and line only, never the matched text. SBOM component entries (`--sbom-components`) are not uploaded.
- TLS is always verified. For a private CA, set `OFFLOAD_CA_CERT=/path/to/ca.pem`. Plain `http://` is refused except to localhost.
- 429 and 5xx responses are retried a bounded number of times. If the combined upload is too large it is resent as one upload per scanner, and if a single scanner's upload is still too large the CLI fails and prints its count. Nothing is truncated.
- Exit codes: if `--fail-on` is hit the exit code is `3`, even when the upload also failed. If only the upload failed it is `4`. The upload runs before the gate, so findings are sent even when the gate fails the job.

In the GitHub Action, add `upload: true`, `platform-url: ${{ vars.OFFLOAD_URL }}` and `api-key: ${{ secrets.OFFLOAD_API_KEY }}`. When the secret is unavailable, for example on pull requests from forks, the Action prints a warning and skips the upload.

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

Every finding carries a stable `finding_fingerprint` (SHA-256 over category + identity, **excluding** tool, severity, and line numbers), a canonical lowercase `severity` (`critical`→`info`), and the software component or file it belongs to. This is the same shape the Offload platform uses, so local results line up with what you see once a repo is connected.

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
