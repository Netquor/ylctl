#!/usr/bin/env bash
# Cut a ylctl release: checks, cross-platform packages, checksums, tag, GitHub release.
#
#   scripts/release.sh v0.1.0                # build, tag v0.1.0, push the tag, publish the release
#   scripts/release.sh v0.2.0 --draft        # same, but the release stays a draft until you publish it
#   scripts/release.sh v0.2.0 --dry-run      # build and checksum into dist/release/ only; no tag, no push
#
# Needs: git, go, gh (authenticated: gh auth status), shasum, tar, zip.
# Run from a clean checkout of main that is up to date with origin.
set -euo pipefail

REPO="Netquor/ylctl"
MODULE="github.com/Netquor/ylctl"
BIN="ylctl"

usage() { sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-2}"; }

VERSION=""; DRAFT=0; DRY=0
for arg in "$@"; do
  case "$arg" in
    --draft) DRAFT=1 ;;
    --dry-run) DRY=1 ;;
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
for os in darwin windows linux; do
  for arch in amd64 arm64; do
    name="${BIN}_${SEMVER}_${os}_${arch}"
    stage="$OUT/stage/$name"
    mkdir -p "$stage"
    exe="$BIN"; [[ "$os" == "windows" ]] && exe="$BIN.exe"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$LDFLAGS" -o "$stage/$exe" ./cmd/ylctl
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
  echo "macOS builds are not signed or notarized. On first run, remove the quarantine flag: \`xattr -d com.apple.quarantine ylctl\`."
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
