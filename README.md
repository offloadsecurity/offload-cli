# offload-cli

[![Release](https://img.shields.io/github/v/release/offloadsecurity/offload-cli?sort=semver)](https://github.com/offloadsecurity/offload-cli/releases)
[![CI](https://github.com/offloadsecurity/offload-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/offloadsecurity/offload-cli/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/offloadsecurity/offload-cli)](LICENSE)

**One command to scan a repo for secrets, vulnerable dependencies, and IaC misconfigurations.** Open source (Apache-2.0), a single static Go binary with no Go dependencies, SARIF-native.

`offload-cli` is the local, developer-facing edge of the [Offload Security](https://offloadsecurity.com) platform — the same detection engines, the same unified finding shape. Run it in your terminal or CI; connect a repo to the platform when you want org-wide correlation, attack-path analysis, and compliance evidence.

```
$ offload scan .

Offload scan  .
  ✓ gitleaks  1 finding(s)
  ✓ grype     9 finding(s)
  ✓ syft      3 component(s)
  ✓ trivy     3 finding(s)

CRITICAL GHSA-jf85-cpcp-j695 in lodash
         lodash@4.17.4 (npm)
         fix: 4.17.12
CRITICAL Uncovered a GitHub Personal Access Token…
         config.py:1
HIGH     Security groups should not allow unrestricted ingress to SSH or RDP…
         main.tf:7
…
Summary: 2 critical  5 high  4 medium  2 low  (13 total)
```

## Why

- **One run, four engines.** Secrets (gitleaks), SBOM (syft), dependency CVEs (grype) and IaC misconfigurations (trivy), without learning four CLIs and four output formats.
- **One deduplicated, severity-ranked list.** Findings from every tool are merged by a scanner-independent fingerprint, so the same issue reported twice shows up once.
- **Honest about coverage.** A scanner that is not installed is reported as *skipped*, never silently counted as zero findings.
- **CI-ready.** SARIF 2.1.0 for GitHub code scanning, `--fail-on` severity gates, and a GitHub Action that installs pinned, checksum-verified tools.
- **Secrets stay redacted.** Secret values are never output in full: only the first and last three characters, in any format.

## Quickstart (30 seconds)

**Docker** (CLI plus all four scanners, nothing else to install):

```bash
docker run --rm -v "$PWD:/src:ro" -v offload-cache:/cache ghcr.io/offloadsecurity/offload-cli scan /src
```

**Homebrew** (macOS / Linux):

```bash
brew install offloadsecurity/tap/offload-cli
brew install gitleaks syft grype trivy      # the scanners it drives
offload scan .
```

**curl** (Linux / macOS, installs to `~/.local/bin`):

```bash
curl -sSfL https://raw.githubusercontent.com/offloadsecurity/offload-cli/main/install.sh | sh -s -- --with-scanners
offload scan .
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

`offload-cli` orchestrates external scanner binaries. Install the ones you want; a missing tool is reported as **skipped**, never silently treated as zero findings.

### install.sh

```bash
# CLI only
curl -sSfL https://raw.githubusercontent.com/offloadsecurity/offload-cli/main/install.sh | sh
# CLI plus the pinned scanners (gitleaks, syft, grype, trivy)
curl -sSfL https://raw.githubusercontent.com/offloadsecurity/offload-cli/main/install.sh | sh -s -- --with-scanners
```

The script detects your OS (Linux, macOS) and architecture (amd64, arm64), downloads the release archive and `checksums.txt`, and refuses to install anything whose SHA-256 does not match. Options: `--version vX.Y.Z`, `--bin-dir DIR`, `--system` (installs to `/usr/local/bin`), `--scanners-only`. Run with `--help` for the full list.

**Verify first.** Prefer to read the script before running it, and to check the release signature yourself:

```bash
curl -sSfLO https://raw.githubusercontent.com/offloadsecurity/offload-cli/main/install.sh
less install.sh
sh install.sh --with-scanners

# Optional: verify the keyless (Sigstore) signature on a release's checksums.txt
V=v0.2.0
curl -sSfLO https://github.com/offloadsecurity/offload-cli/releases/download/$V/checksums.txt
curl -sSfLO https://github.com/offloadsecurity/offload-cli/releases/download/$V/checksums.txt.sigstore.json
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity "https://github.com/offloadsecurity/offload-cli/.github/workflows/release.yml@refs/tags/$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Homebrew

```bash
brew install offloadsecurity/tap/offload-cli
brew install gitleaks syft grype trivy
```

### Go / prebuilt binaries

```bash
go install github.com/offloadsecurity/offload-cli@latest   # Go 1.26+; installs the binary as `offload-cli`
```

Or download a prebuilt binary (Linux, macOS, Windows; amd64 and arm64) from [Releases](https://github.com/offloadsecurity/offload-cli/releases).

### Docker

`ghcr.io/offloadsecurity/offload-cli` (linux/amd64, linux/arm64) bundles the CLI and the pinned scanners on Alpine, runs as a non-root user (uid 10001), and uses `/src` as its working directory:

```bash
docker run --rm -v "$PWD:/src:ro" -v offload-cache:/cache ghcr.io/offloadsecurity/offload-cli scan /src
docker run --rm -v "$PWD:/src:ro" -v offload-cache:/cache ghcr.io/offloadsecurity/offload-cli scan /src --format sarif > offload.sarif
```

The vulnerability databases are **not** baked into the image, so results are never older than your last run. On first run grype and trivy download their databases into `/cache` (in our test, this took about a minute, and the grype database used about 3 GB on disk). Mount a named volume at `/cache`, as above, so later runs reuse it and only fetch updates. Write output to stdout (as above) rather than `--output`, since the container user usually cannot write to your mounted directory.

Release images are signed with keyless cosign and carry SBOM and provenance attestations:

```bash
cosign verify ghcr.io/offloadsecurity/offload-cli:v0.2.0 \
  --certificate-identity "https://github.com/offloadsecurity/offload-cli/.github/workflows/release.yml@refs/tags/v0.2.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Pinned scanner versions

The Action, the Docker image and `install.sh --with-scanners` all read one file, [`scanners.env`](scanners.env). It pins each tool's version and the SHA-256 of that release's published checksums file; every archive is verified against it before use, and any mismatch stops the install. To bump, run `scripts/update-scanners.sh GITLEAKS SYFT GRYPE TRIVY` (versions without the `v`), review the upstream release notes, and open a PR.

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
permissions:
  contents: read
  security-events: write   # for upload-sarif
jobs:
  offload:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: offloadsecurity/offload-cli@v0.2.0
        with:
          path: .
          fail-on: high
          sarif-file: offload.sarif
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: offload.sarif
```

The Action downloads the prebuilt `offload` release binary that matches the tag you pinned, plus the pinned scanners, verifying each against its published checksums, so no `setup-go` is needed. It runs on Linux (x64, arm64) and macOS runners.

If you pin the Action to a commit SHA or a branch instead of a release tag, there is no matching release to download. Either set `cli-version: v0.2.0` to use the prebuilt binary, or add `actions/setup-go` before the step and the Action builds the CLI from its own source.

| Input | Description | Default |
|---|---|---|
| `path` | directory to scan | `.` |
| `scanners` | comma list: `secrets,sbom,sca,iac` | all |
| `fail-on` | fail the job at or above this severity; empty = never | `high` |
| `format` | log output: `table` \| `json` \| `sarif` | `table` |
| `sarif-file` | also write SARIF here (written even when `fail-on` trips) | none |
| `cli-version` | release of the CLI to download, e.g. `v0.2.0` | the action ref |

<!-- Feature sections (e.g. "Secret verdicts", "Send results to Offload") go below this line. -->

## The finding model

Every finding carries a stable `finding_fingerprint` (SHA-256 over category + identity, **excluding** tool, severity, and line numbers), a canonical lowercase `severity` (`critical`→`info`), and the software component or file it belongs to. This is the same shape the Offload platform uses, so local results line up with what you see once a repo is connected.

## From local scan to a governed program

`offload-cli` gives you the detection edge for free. The [Offload platform](https://offloadsecurity.com) adds what a single scan can't: deduplicated risk across every repo and cloud account, identity-aware attack paths to crown-jewel assets, and compliance evidence mapped to frameworks — SaaS or fully on-premises.

## Built on

offload-cli stands on excellent open-source tools, which it runs as external
programs (the `offload` binary does not embed them; the Docker image
redistributes their official, unmodified release binaries with their licences):
[syft](https://github.com/anchore/syft) & [grype](https://github.com/anchore/grype)
(Apache-2.0, © Anchore), [trivy](https://github.com/aquasecurity/trivy)
(Apache-2.0, © Aqua Security), and [gitleaks](https://github.com/gitleaks/gitleaks)
(MIT). offload-cli is not affiliated with or endorsed by these projects; names
are used only to describe what it wraps. See [NOTICE](NOTICE).

## License

[Apache License 2.0](LICENSE). Contributions welcome.
