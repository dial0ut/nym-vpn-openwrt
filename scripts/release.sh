#!/bin/bash
# Cut a release: bump version, promote changelog, push develop, fast-forward
# openwrt, tag. The tag push triggers .github/workflows/release-musl.yml.
#
# Usage: release.sh <version> [--dry-run]
#
#   version    - New version, no 'v' prefix (e.g., "1.31.0")
#   --dry-run  - Print every mutating command instead of running it

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CARGO_TOML="$REPO_ROOT/nym-vpn-core/Cargo.toml"
CHANGELOG="$REPO_ROOT/CHANGELOG.md"

DRY_RUN=0
VERSION=""
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -*) echo "Unknown flag: $arg"; exit 1 ;;
        *) VERSION="$arg" ;;
    esac
done

if [ -z "$VERSION" ]; then
    echo "Usage: $0 <version> [--dry-run]"
    exit 1
fi

if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
    echo "Error: '$VERSION' is not a valid version (expected X.Y.Z, no 'v' prefix)"
    exit 1
fi

TAG="v$VERSION"

run() {
    if [ "$DRY_RUN" = 1 ]; then
        echo "[dry-run] $*"
    else
        echo "+ $*"
        "$@"
    fi
}

fail() {
    echo ""
    echo "ABORT: $*" >&2
    exit 1
}

cd "$REPO_ROOT"

echo "=== Preflight ==="

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[ "$BRANCH" = "develop" ] || fail "must be on 'develop' (currently on '$BRANCH')"

git diff-index --quiet HEAD -- || fail "working tree is dirty — commit or stash first"

echo "Fetching origin..."
git fetch origin

[ "$(git rev-parse develop)" = "$(git rev-parse origin/develop)" ] \
    || fail "local develop != origin/develop — pull or push first"

# The tag push builds every target, but only once the tag exists. Refuse to
# tag what CI (tests plus the armv7 and mipsel cross-builds) has not passed.
# Docs-only pushes skip CI, so use the newest commit that ran it and require
# that only docs changed since.
command -v gh >/dev/null 2>&1 || fail "gh is required to check CI on develop (https://cli.github.com)"
command -v jq >/dev/null 2>&1 || fail "jq is required to check CI on develop"
echo "Checking CI on develop..."
CI_RUNS="$(gh run list --workflow ci.yml --branch develop --limit 50 \
    --json headSha,status,conclusion,url)" || fail "could not list CI runs"
CI_SHA="" CI_RUN=""
for sha in $(git rev-list --max-count=50 HEAD); do
    CI_RUN="$(jq -c --arg s "$sha" 'map(select(.headSha == $s)) | first // empty' <<< "$CI_RUNS")"
    if [ -n "$CI_RUN" ]; then CI_SHA="$sha"; break; fi
done
[ -n "$CI_SHA" ] || fail "no CI run found for any of develop's last 50 commits"
UNTESTED="$(git diff --name-only "$CI_SHA" HEAD -- . ':(exclude)docs/**' ':(exclude,glob)*.md')"
[ -z "$UNTESTED" ] || fail "CI has not run on $(git rev-parse --short HEAD) yet (last run: ${CI_SHA:0:9}); wait for it.
Changed since: $(echo "$UNTESTED" | tr '\n' ' ')"
CI_STATUS="$(jq -r .status <<< "$CI_RUN")"
CI_CONCLUSION="$(jq -r .conclusion <<< "$CI_RUN")"
CI_URL="$(jq -r .url <<< "$CI_RUN")"
[ "$CI_STATUS" = completed ] || fail "CI on ${CI_SHA:0:9} is still $CI_STATUS; wait for it: $CI_URL"
[ "$CI_CONCLUSION" = success ] || fail "CI on ${CI_SHA:0:9} concluded '$CI_CONCLUSION': $CI_URL"
echo "CI passed on ${CI_SHA:0:9}: $CI_URL"

git merge-base --is-ancestor origin/openwrt develop \
    || fail "origin/openwrt is not an ancestor of develop — the fast-forward invariant is broken.
Fix manually (openwrt must be a strict subset of develop; never commit to it directly)."

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
    fail "tag $TAG already exists"
fi
if git ls-remote --exit-code --tags origin "refs/tags/$TAG" >/dev/null 2>&1; then
    fail "tag $TAG already exists on origin"
fi

CURRENT_VERSION="$(grep -m1 '^version = ' "$CARGO_TOML" | cut -d'"' -f2)"
[ -n "$CURRENT_VERSION" ] || fail "could not parse workspace version from $CARGO_TOML"
[ "$VERSION" != "$CURRENT_VERSION" ] || fail "version $VERSION is already the current version"
NEWEST="$(printf '%s\n%s\n' "$CURRENT_VERSION" "$VERSION" | sort -V | tail -1)"
[ "$NEWEST" = "$VERSION" ] || fail "version $VERSION is older than current $CURRENT_VERSION"

[ -f "$CHANGELOG" ] || fail "CHANGELOG.md not found"
UNRELEASED="$(awk '/^## \[Unreleased\]/{found=1; next} /^## \[/{exit} found' "$CHANGELOG" \
    | grep -vE '^(###|[[:space:]]*$)' || true)"
[ -n "$UNRELEASED" ] || fail "CHANGELOG.md has an empty [Unreleased] section — write the release notes first"

echo ""
echo "Releasing $CURRENT_VERSION -> $VERSION ($TAG)"
echo ""
echo "Unreleased changelog entries:"
echo "$UNRELEASED" | sed 's/^/  /'
echo ""

if [ "$DRY_RUN" = 0 ]; then
    printf "Proceed? [y/N] "
    read -r REPLY
    case "$REPLY" in y|Y|yes) ;; *) echo "Cancelled."; exit 1 ;; esac
fi

echo ""
echo "=== Bump ==="

if [ "$DRY_RUN" = 1 ]; then
    echo "[dry-run] set version = \"$VERSION\" in $CARGO_TOML"
    echo "[dry-run] (cd nym-vpn-core && cargo update --workspace)"
    echo "[dry-run] promote CHANGELOG [Unreleased] -> [$VERSION] - $(date +%Y-%m-%d)"
else
    awk -v old="$CURRENT_VERSION" -v new="$VERSION" '
        !done && $0 == "version = \"" old "\"" { $0 = "version = \"" new "\""; done=1 }
        { print }
    ' "$CARGO_TOML" > "$CARGO_TOML.tmp" && mv "$CARGO_TOML.tmp" "$CARGO_TOML"
    grep -q "^version = \"$VERSION\"" "$CARGO_TOML" || fail "version bump in Cargo.toml failed"

    # Never cargo generate-lockfile: it re-resolves everything from scratch.
    (cd "$REPO_ROOT/nym-vpn-core" && cargo update --workspace)

    TODAY="$(date +%Y-%m-%d)"
    awk -v ver="$VERSION" -v date="$TODAY" '
        { print }
        /^## \[Unreleased\]/ && !done { print ""; print "## [" ver "] - " date; done=1 }
    ' "$CHANGELOG" > "$CHANGELOG.tmp" && mv "$CHANGELOG.tmp" "$CHANGELOG"
    grep -q "^## \[$VERSION\]" "$CHANGELOG" || fail "changelog promotion failed"
fi

run git add "$CARGO_TOML" "$REPO_ROOT/nym-vpn-core/Cargo.lock" "$CHANGELOG"
run git commit -m "chore: bump version to $VERSION"

echo ""
echo "=== Ship ==="

run git push origin develop
# Plain (non-force) push: succeeds only as a fast-forward, enforcing the invariant.
run git push origin develop:openwrt
run git tag -a "$TAG" -m "$TAG"
run git push origin "$TAG"

echo ""
echo "=== Done ==="
echo "Release pipeline: https://github.com/dial0ut/nym-vpn-openwrt/actions/workflows/release-musl.yml"
