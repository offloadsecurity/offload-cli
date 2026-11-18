#!/bin/sh
# install.sh: install the offload CLI (and, optionally, the scanners it drives)
# from GitHub Releases, verifying every download against a published SHA-256
# checksum before it is used. Any mismatch aborts the install (fail closed).
#
#   curl -sSfL https://raw.githubusercontent.com/offloadsecurity/offload-cli/main/install.sh | sh
#   curl -sSfL https://raw.githubusercontent.com/offloadsecurity/offload-cli/main/install.sh | sh -s -- --with-scanners
#
# Run `sh install.sh --help` for all options. POSIX sh; needs curl (or wget),
# tar, and sha256sum (or shasum).

set -eu

REPO="offloadsecurity/offload-cli"
GH="https://github.com"
RAW="https://raw.githubusercontent.com"

VERSION=""
BIN_DIR=""
SYSTEM=0
WITH_CLI=1
WITH_SCANNERS=0
SCANNERS_ENV=""
LICENSES_DIR=""
OS=""
ARCH=""

usage() {
	cat <<'EOF'
Install offload-cli from GitHub Releases, with checksum verification.

Usage: install.sh [options]

  -v, --version TAG        offload-cli release to install, e.g. v0.2.0 (default: latest)
  -b, --bin-dir DIR        install directory (default: ~/.local/bin)
      --system             install into /usr/local/bin (uses sudo if it is not writable)
      --with-scanners      also install the pinned gitleaks, syft, grype and trivy
      --scanners-only      install only the pinned scanners, not the CLI
      --scanners-env FILE  read scanner pins from FILE (default: scanners.env from the
                           release tag being installed)
      --licenses-dir DIR   also copy each scanner's LICENSE to DIR/<tool>/LICENSE
      --os OS              override OS detection (linux | darwin)
      --arch ARCH          override arch detection (amd64 | arm64)
  -h, --help               show this help
EOF
}

log() { printf '%s\n' "$*" >&2; }
die() {
	log "install.sh: error: $*"
	exit 1
}

need_arg() { [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"; }

while [ $# -gt 0 ]; do
	case "$1" in
	-v | --version) need_arg "$@"; VERSION=$2; shift 2 ;;
	-b | --bin-dir) need_arg "$@"; BIN_DIR=$2; shift 2 ;;
	--system) SYSTEM=1; shift ;;
	--with-scanners) WITH_SCANNERS=1; shift ;;
	--scanners-only) WITH_SCANNERS=1; WITH_CLI=0; shift ;;
	--scanners-env) need_arg "$@"; SCANNERS_ENV=$2; shift 2 ;;
	--licenses-dir) need_arg "$@"; LICENSES_DIR=$2; shift 2 ;;
	--os) need_arg "$@"; OS=$2; shift 2 ;;
	--arch) need_arg "$@"; ARCH=$2; shift 2 ;;
	-h | --help) usage; exit 0 ;;
	*) usage >&2; die "unknown option: $1" ;;
	esac
done

# ---- platform -------------------------------------------------------------

if [ -z "$OS" ]; then
	case "$(uname -s)" in
	Linux) OS=linux ;;
	Darwin) OS=darwin ;;
	*) die "unsupported OS $(uname -s): download a release from $GH/$REPO/releases" ;;
	esac
fi
if [ -z "$ARCH" ]; then
	case "$(uname -m)" in
	x86_64 | amd64) ARCH=amd64 ;;
	aarch64 | arm64) ARCH=arm64 ;;
	*) die "unsupported architecture $(uname -m)" ;;
	esac
fi
case "$OS" in linux | darwin) ;; *) die "unsupported --os $OS (linux | darwin)" ;; esac
case "$ARCH" in amd64 | arm64) ;; *) die "unsupported --arch $ARCH (amd64 | arm64)" ;; esac

# ---- tools ----------------------------------------------------------------

if command -v curl >/dev/null 2>&1; then
	DL=curl
elif command -v wget >/dev/null 2>&1; then
	DL=wget
else
	die "need curl or wget"
fi
command -v tar >/dev/null 2>&1 || die "need tar"
if command -v sha256sum >/dev/null 2>&1; then
	SHA="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
	SHA="shasum -a 256"
else
	die "need sha256sum or shasum to verify downloads"
fi

# fetch URL DEST: HTTPS only, fail on any HTTP error.
fetch() {
	case "$1" in https://*) ;; *) die "refusing non-HTTPS URL $1" ;; esac
	if [ "$DL" = curl ]; then
		curl -sSfL --proto '=https' --tlsv1.2 --retry 3 -o "$2" "$1" || die "download failed: $1"
	else
		wget -q --https-only -O "$2" "$1" || die "download failed: $1"
	fi
}

sha256_of() { $SHA "$1" | awk '{print $1}'; }

# verify FILE NAME SUMS: FILE's SHA-256 must equal the entry for NAME in SUMS.
verify() {
	want=$(awk -v n="$2" '{f=$2; sub(/^\*/, "", f)} f == n {print $1; exit}' "$3")
	[ -n "$want" ] || die "no checksum for $2 in $(basename "$3"): refusing to install"
	got=$(sha256_of "$1")
	[ "$got" = "$want" ] || die "checksum mismatch for $2 (want $want, got $got): refusing to install"
	log "  verified $2 (sha256 $got)"
}

# latest_tag: resolve the newest offload-cli release tag.
latest_tag() {
	if [ "$DL" = curl ]; then
		u=$(curl -sSfLI --proto '=https' -o /dev/null -w '%{url_effective}' "$GH/$REPO/releases/latest") ||
			die "could not resolve the latest release; pass --version"
		t=${u##*/}
	else
		t=$(wget -q -O - "https://api.github.com/repos/$REPO/releases/latest" |
			sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
	fi
	case "$t" in v[0-9]*) printf '%s\n' "$t" ;; *) die "could not resolve the latest release; pass --version" ;; esac
}

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t offload-install)
trap 'rm -rf "$TMP"' EXIT INT TERM

if [ "$WITH_CLI" = 1 ] || [ -z "$SCANNERS_ENV" ]; then
	[ -n "$VERSION" ] || VERSION=$(latest_tag)
	case "$VERSION" in v*) ;; *) VERSION="v$VERSION" ;; esac
fi

if [ -z "$BIN_DIR" ]; then
	if [ "$SYSTEM" = 1 ]; then BIN_DIR=/usr/local/bin; else BIN_DIR="$HOME/.local/bin"; fi
fi
SUDO=""
mkdir -p "$BIN_DIR" 2>/dev/null || true
if [ ! -w "$BIN_DIR" ]; then
	if [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1; then
		SUDO=sudo
		log "$BIN_DIR is not writable; using sudo to install"
		$SUDO mkdir -p "$BIN_DIR"
	else
		die "$BIN_DIR is not writable (try --bin-dir DIR)"
	fi
fi

# put SRC NAME: install an executable into BIN_DIR.
put() {
	$SUDO cp "$1" "$BIN_DIR/$2.tmp.$$"
	$SUDO chmod 0755 "$BIN_DIR/$2.tmp.$$"
	$SUDO mv -f "$BIN_DIR/$2.tmp.$$" "$BIN_DIR/$2"
	log "  installed $BIN_DIR/$2"
}

# ---- offload CLI ----------------------------------------------------------

if [ "$WITH_CLI" = 1 ]; then
	v=${VERSION#v}
	archive="offload-cli_${v}_${OS}_${ARCH}.tar.gz"
	base="$GH/$REPO/releases/download/$VERSION"
	log "offload-cli $VERSION ($OS/$ARCH)"
	mkdir -p "$TMP/cli"
	fetch "$base/checksums.txt" "$TMP/cli/checksums.txt"
	fetch "$base/$archive" "$TMP/cli/$archive"
	verify "$TMP/cli/$archive" "$archive" "$TMP/cli/checksums.txt"
	tar -xzf "$TMP/cli/$archive" -C "$TMP/cli" offload || die "offload binary not found in $archive"
	put "$TMP/cli/offload" offload
fi

# ---- scanners -------------------------------------------------------------

# pin KEY: read KEY from the scanners env file. Parsed, never sourced.
pin() {
	val=$(sed -n "s/^$1=\([A-Za-z0-9._-]*\)[[:space:]]*\$/\1/p" "$SCANNERS_ENV" | head -n 1)
	[ -n "$val" ] || die "$1 missing from $SCANNERS_ENV"
	printf '%s\n' "$val"
}

# scanner TOOL REPO VERSION CHECKSUMS_SHA256 ASSET
scanner() {
	tool=$1 repo=$2 ver=$3 sums_pin=$4 asset=$5
	d="$TMP/$tool"
	mkdir -p "$d"
	base="$GH/$repo/releases/download/v$ver"
	sums="${tool}_${ver}_checksums.txt"
	log "$tool v$ver"
	fetch "$base/$sums" "$d/$sums"
	# The checksums file itself is pinned in scanners.env, so a release asset
	# replaced after we pinned it is detected too.
	got=$(sha256_of "$d/$sums")
	[ "$got" = "$sums_pin" ] || die "checksum mismatch for $sums (pinned $sums_pin, got $got): refusing to install"
	fetch "$base/$asset" "$d/$asset"
	verify "$d/$asset" "$asset" "$d/$sums"
	tar -xzf "$d/$asset" -C "$d" "$tool" || die "$tool binary not found in $asset"
	put "$d/$tool" "$tool"
	if [ -n "$LICENSES_DIR" ]; then
		tar -xzf "$d/$asset" -C "$d" LICENSE || die "LICENSE not found in $asset"
		mkdir -p "$LICENSES_DIR/$tool"
		cp "$d/LICENSE" "$LICENSES_DIR/$tool/LICENSE"
	fi
}

if [ "$WITH_SCANNERS" = 1 ]; then
	if [ -z "$SCANNERS_ENV" ]; then
		SCANNERS_ENV="$TMP/scanners.env"
		fetch "$RAW/$REPO/$VERSION/scanners.env" "$SCANNERS_ENV"
	fi
	[ -r "$SCANNERS_ENV" ] || die "cannot read $SCANNERS_ENV"

	case "$ARCH" in amd64) gl_arch=x64 tv_arch=64bit ;; arm64) gl_arch=arm64 tv_arch=ARM64 ;; esac
	case "$OS" in linux) tv_os=Linux ;; darwin) tv_os=macOS ;; esac

	v=$(pin GITLEAKS_VERSION)
	scanner gitleaks gitleaks/gitleaks "$v" "$(pin GITLEAKS_CHECKSUMS_SHA256)" "gitleaks_${v}_${OS}_${gl_arch}.tar.gz"
	v=$(pin SYFT_VERSION)
	scanner syft anchore/syft "$v" "$(pin SYFT_CHECKSUMS_SHA256)" "syft_${v}_${OS}_${ARCH}.tar.gz"
	v=$(pin GRYPE_VERSION)
	scanner grype anchore/grype "$v" "$(pin GRYPE_CHECKSUMS_SHA256)" "grype_${v}_${OS}_${ARCH}.tar.gz"
	v=$(pin TRIVY_VERSION)
	scanner trivy aquasecurity/trivy "$v" "$(pin TRIVY_CHECKSUMS_SHA256)" "trivy_${v}_${tv_os}-${tv_arch}.tar.gz"
fi

# ---- next steps -----------------------------------------------------------

case ":$PATH:" in
*":$BIN_DIR:"*) path_note="" ;;
*) path_note="  Add it to your PATH:  export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

log ""
log "Done. Installed into $BIN_DIR"
[ -z "$path_note" ] || log "$path_note"
if [ "$WITH_CLI" = 1 ]; then
	log ""
	log "Next steps:"
	log "  offload scan ."
	if [ "$WITH_SCANNERS" = 0 ]; then
		log ""
		log "offload drives gitleaks, syft, grype and trivy; a missing one is reported as skipped."
		log "Get them with one of:"
		log "  curl -sSfL $RAW/$REPO/main/install.sh | sh -s -- --scanners-only --version $VERSION"
		log "  brew install gitleaks syft grype trivy"
		log "Or skip local installs and use the image, which bundles all four:"
		log "  docker run --rm -v \"\$PWD:/src\" ghcr.io/$REPO:$VERSION scan /src"
	fi
fi
