#!/usr/bin/env bash
# Cut a ylctl release: checks, cross-platform packages, checksums, tag, GitHub release.
#
#   scripts/release.sh v0.1.0                # build, tag v0.1.0, push the tag, publish the release
#   scripts/release.sh v0.2.0 --draft        # same, but the release stays a draft until you publish it
#   scripts/release.sh v0.2.0 --dry-run      # build, sign and checksum into dist/release/ only; no tag, no push, no notarization
#   Options: --no-sign (skip the Developer ID signature), --no-notarize (sign but do not notarize)
#   Signing uses SIGN_IDENTITY; notarization uses the keychain profile NOTARY_PROFILE (default ylctl-notary).
#
# Needs: git, go, gh (authenticated: gh auth status), shasum, tar, zip.
# Run from a clean checkout of main that is up to date with origin.
set -euo pipefail

REPO="Netquor/ylctl"
MODULE="github.com/Netquor/ylctl"
BIN="ylctl"

usage() { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }

VERSION=""; DRAFT=0; DRY=0; SIGN=1
# macOS signing. SIGN_IDENTITY overrides the default Developer ID Application identity.
# NOTARY_PROFILE is a keychain profile for xcrun notarytool (create it once with
# `xcrun notarytool store-credentials`); when it is set, the signed macOS binaries are notarized too.
SIGN_IDENTITY="${SIGN_IDENTITY:-Developer ID Application: Netquor Technologies LLC (9M93S6CWDT)}"
NOTARY_PROFILE="${NOTARY_PROFILE:-ylctl-notary}"
NOTARIZE=1
for arg in "$@"; do
  case "$arg" in
    --draft) DRAFT=1 ;;
    --dry-run) DRY=1 ;;
    --no-sign) SIGN=0 ;;
    --no-notarize) NOTARIZE=0 ;;
    -h|--help) usage 0 ;;
    v[0-9]*) VERSION="$arg" ;;
    *) echo "unknown argument: $arg" >&2; usage ;;
  esac
done
[[ -n "$VERSION" ]] || usage
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "version must look like v1.2.3 (got $VERSION)" >&2; exit 2; }
SEMVER="${VERSION#v}"

root="$(git rev-parse --show-toplevel)"
cd "$root"

say() { printf '\n==> %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

# ---- preflight ---------------------------------------------------------------
say "preflight"
command -v gh >/dev/null || die "gh is not installed (https://cli.github.com)"
command -v go >/dev/null || die "go is not installed"
gh auth status >/dev/null 2>&1 || die "gh is not logged in: run gh auth login"
if [[ $SIGN -eq 1 ]]; then
  command -v codesign >/dev/null || die "codesign is not available (Xcode command line tools)"
  security find-identity -v -p codesigning | grep -F "\"$SIGN_IDENTITY\"" >/dev/null \
    || die "signing identity not in the keychain: $SIGN_IDENTITY (set SIGN_IDENTITY or use --no-sign)"
  echo "  signing macOS binaries as: $SIGN_IDENTITY"
  if [[ $NOTARIZE -eq 1 ]]; then
    xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1 \
      || die "notarization needs a stored Apple credential, profile '$NOTARY_PROFILE'. Create it once: xcrun notarytool store-credentials \"$NOTARY_PROFILE\"  (or set NOTARY_PROFILE, or pass --no-notarize)"
    echo "  notarizing with keychain profile: $NOTARY_PROFILE"
  else
    echo "  notarization skipped (--no-notarize)"
  fi
fi
if [[ $DRY -eq 0 ]]; then
  [[ -z "$(git status --porcelain --untracked-files=no)" ]] || die "working tree has changes to tracked files; commit or stash first"
  [[ "$(git rev-parse --abbrev-ref HEAD)" == "main" ]] || die "release from main (you are on $(git rev-parse --abbrev-ref HEAD))"
  git fetch --quiet origin main
  [[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/main)" ]] || die "HEAD is not origin/main; push or pull first"
  git rev-parse -q --verify "refs/tags/$VERSION" >/dev/null && die "tag $VERSION already exists locally"
  git ls-remote --exit-code --tags origin "refs/tags/$VERSION" >/dev/null 2>&1 && die "tag $VERSION already exists on origin"
  gh release view "$VERSION" --repo "$REPO" >/dev/null 2>&1 && die "release $VERSION already exists on $REPO"
fi

say "checks: gofmt, vet, race tests"
test -z "$(gofmt -l .)" || { gofmt -l .; die "gofmt needed"; }
go vet ./...
go test -race -count=1 ./...

# ---- build -------------------------------------------------------------------
COMMIT="$(git rev-parse --short HEAD)"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X $MODULE/internal/cli.Version=$VERSION -X $MODULE/internal/cli.Commit=$COMMIT -X $MODULE/internal/cli.Date=$DATE"
OUT="$root/dist/release/$VERSION"
rm -rf "$OUT"; mkdir -p "$OUT/stage"

say "building packages into $OUT"
SIGNED_DARWIN=()
for os in darwin windows linux; do
  for arch in amd64 arm64; do
    name="${BIN}_${SEMVER}_${os}_${arch}"
    stage="$OUT/stage/$name"
    mkdir -p "$stage"
    exe="$BIN"; [[ "$os" == "windows" ]] && exe="$BIN.exe"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" -o "$stage/$exe" ./cmd/ylctl
    if [[ "$os" == "darwin" && $SIGN -eq 1 ]]; then
      # Hardened runtime and a secure timestamp are required for notarization. Sign before archiving.
      codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$stage/$exe"
      codesign --verify --strict --verbose=2 "$stage/$exe" 2>&1 | sed 's/^/    /'
      SIGNED_DARWIN+=("$stage/$exe")
    fi
    cp LICENSE README.md docs/commands.md "$stage/"
    if [[ "$os" == "windows" ]]; then
      (cd "$OUT/stage" && zip -qr "$OUT/$name.zip" "$name")
    else
      tar -C "$OUT/stage" -czf "$OUT/$name.tar.gz" "$name"
    fi
    echo "  $name"
  done
done
rm -rf "$OUT/stage"
echo "  signed macOS binaries: ${#SIGNED_DARWIN[@]}"

# ---- notarize (optional) -----------------------------------------------------
NOTARIZED=0
if [[ $SIGN -eq 1 && $NOTARIZE -eq 1 && $DRY -eq 0 ]]; then
  say "notarizing the signed macOS binaries"
  NZIP="$OUT/notarize.zip"
  NTMP="$(mktemp -d)"
  rm -f "$NZIP"
  # notarytool takes an archive. The ticket is keyed to the signed binary, so the release archives
  # built from these same binaries are covered as well.
  for b in "${SIGNED_DARWIN[@]}"; do
    cp "$b" "$NTMP/$(basename "$(dirname "$b")")"
  done
  ditto -c -k "$NTMP" "$NZIP"
  RESULT="$(xcrun notarytool submit "$NZIP" --keychain-profile "$NOTARY_PROFILE" --wait 2>&1)"
  echo "$RESULT" | sed 's/^/    /'
  echo "$RESULT" | grep -q "status: Accepted" || die "notarization was not accepted; see the log above (xcrun notarytool log <id> --keychain-profile $NOTARY_PROFILE)"
  NOTARIZED=1
  rm -f "$NZIP"; rm -rf "$NTMP"
fi

# ---- checksums ---------------------------------------------------------------
say "checksums"
(cd "$OUT" && shasum -a 256 ./*.tar.gz ./*.zip | sed 's| \./| |' > checksums.txt)
cat "$OUT/checksums.txt"

# ---- publish -----------------------------------------------------------------
if [[ $DRY -eq 1 ]]; then
  say "dry run: nothing tagged, pushed or published. Artifacts are in $OUT"
  exit 0
fi

PREV="$(git describe --tags --abbrev=0 2>/dev/null || true)"
NOTES="$OUT/notes.md"
{
  echo "## ylctl $VERSION"
  echo
  echo "Download the archive for your system, then check it against \`checksums.txt\`."
  echo "Archives: \`tar.gz\` for macOS and Linux, \`zip\` for Windows. Each contains the \`ylctl\` binary, LICENSE, README and the command reference."
  echo
  if [[ $SIGN -eq 1 ]]; then
    echo "macOS binaries are signed with a Developer ID certificate$([[ $NOTARIZED -eq 1 ]] && echo " and notarized by Apple")."
  else
    echo "macOS binaries are not signed (built with --no-sign). On first run, remove the quarantine flag: \`xattr -d com.apple.quarantine ylctl\`."
  fi
  echo
  if [[ -n "$PREV" ]]; then
    echo "### Changes since $PREV"
    git log --no-merges --pretty='- %s' "$PREV..HEAD"
  else
    echo "### Changes"
    git log --no-merges --pretty='- %s' HEAD
  fi
} > "$NOTES"

say "tag $VERSION and push"
git tag -a "$VERSION" -m "ylctl $VERSION"
git push origin "$VERSION"

say "publish GitHub release"
args=(--repo "$REPO" --title "ylctl $VERSION" --notes-file "$NOTES" --verify-tag)
[[ $DRAFT -eq 1 ]] && args+=(--draft)
gh release create "$VERSION" "${args[@]}" "$OUT"/*.tar.gz "$OUT"/*.zip "$OUT/checksums.txt"

say "done"
gh release view "$VERSION" --repo "$REPO" --web >/dev/null 2>&1 || true
gh release view "$VERSION" --repo "$REPO" --json url --jq .url
