#!/bin/sh
# update-scanners.sh: re-pin the bundled scanners in scanners.env.
#
#   scripts/update-scanners.sh GITLEAKS_VER SYFT_VER GRYPE_VER TRIVY_VER
#   scripts/update-scanners.sh 8.30.1 1.57.1 0.121.3 0.76.2
#
# For each tool it downloads the release's published checksums file and pins
# that file's SHA-256 next to the version. install.sh (used by the Action and
# the Dockerfile) then refuses any checksums file or archive that differs.
# Review the upstream release notes, and prefer releases at least ~7 days old.
set -eu

[ $# -eq 4 ] || {
	sed -n '2,10p' "$0" >&2
	exit 2
}

root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/scanners.env"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT INT TERM

if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"; else SHA="shasum -a 256"; fi

sum_of() { # REPO TOOL VERSION
	case "$3" in v*) echo "use versions without a leading v: $3" >&2; exit 2 ;; esac
	f="$tmp/$2_$3_checksums.txt"
	curl -sSfL --proto '=https' -o "$f" "https://github.com/$1/releases/download/v$3/$2_$3_checksums.txt"
	$SHA "$f" | awk '{print $1}'
}

gl=$(sum_of gitleaks/gitleaks gitleaks "$1")
sy=$(sum_of anchore/syft syft "$2")
gr=$(sum_of anchore/grype grype "$3")
tv=$(sum_of aquasecurity/trivy trivy "$4")

cat >"$out" <<ENV
# Pinned third-party scanners: the single source of truth for the GitHub
# Action, the Docker image and install.sh --with-scanners.
#
# Each *_CHECKSUMS_SHA256 is the SHA-256 of that release's published
# checksums file; every archive is then verified against that file before use.
# Do not edit by hand. To bump, run:
#   scripts/update-scanners.sh GITLEAKS SYFT GRYPE TRIVY
# (versions without a leading "v"), review the upstream release notes, and
# prefer releases at least ~7 days old.
#
# Parsed with sed, never sourced: KEY=value lines only.

GITLEAKS_VERSION=$1
GITLEAKS_CHECKSUMS_SHA256=$gl
SYFT_VERSION=$2
SYFT_CHECKSUMS_SHA256=$sy
GRYPE_VERSION=$3
GRYPE_CHECKSUMS_SHA256=$gr
TRIVY_VERSION=$4
TRIVY_CHECKSUMS_SHA256=$tv
ENV
echo "wrote $out" >&2
