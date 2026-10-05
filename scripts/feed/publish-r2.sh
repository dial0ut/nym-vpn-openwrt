#!/bin/bash
# Publish a release's opkg and apk feeds, install.sh and `latest` to R2
# (packages.dial0ut.org).
#
# install.sh reads `latest`, then fetches that version from the feed, so: add
# the new packages and indexes, move `latest`, and only then delete what this
# release does not have.
#
# Not `aws s3 sync --delete`: sync walks the local and remote listings in step
# assuming byte order, and R2 lists Packages after Packages.gz and
# Packages.sig. v1.35.0's sync uploaded and deleted each Packages in parallel
# and lost it in 12 of 21 opkg directories. Prune by set difference instead,
# then fail unless R2 holds exactly the feed that was built (keys and sizes).
#
# Only opkg/, apk/, install.sh and latest are touched; anything else in the
# bucket (toolchains/, ...) is left alone.
#
# Usage: publish-r2.sh <feed_dir> <tag>
#   R2_BUCKET, R2_ENDPOINT  and AWS credentials for them in the environment
set -euo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 <feed_dir> <tag>" >&2
    exit 2
fi
FEED_DIR="$1"
TAG="$2"
: "${R2_BUCKET:?R2_BUCKET is not set}" "${R2_ENDPOINT:?R2_ENDPOINT is not set}"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
export LC_ALL=C

s3() { aws s3 "$@" --endpoint-url "$R2_ENDPOINT"; }

# "<key> <size>" for every file of one feed, sorted
local_objects() {
    (cd "$FEED_DIR" && find "$1" -type f -printf '%p %s\n') | sort
}

remote_objects() {
    aws s3api list-objects-v2 --bucket "$R2_BUCKET" --prefix "$1/" \
        --endpoint-url "$R2_ENDPOINT" --query 'Contents[].[Key,Size]' --output json \
        | jq -r '.[]? | "\(.[0]) \(.[1])"' | sort
}

keys() { cut -d' ' -f1; }

# An empty feed would prune the live one to nothing.
for feed in opkg apk; do
    [ -n "$(local_objects "$feed")" ] \
        || { echo "::error::$FEED_DIR/$feed is empty; refusing to publish" >&2; exit 1; }
done

for feed in opkg apk; do
    s3 cp --recursive "$FEED_DIR/$feed/" "s3://$R2_BUCKET/$feed/"
done

s3 cp "$REPO_ROOT/scripts/install.sh" "s3://$R2_BUCKET/install.sh"

latest="$(mktemp)"
trap 'rm -f "$latest"' EXIT
printf '%s\n' "$TAG" > "$latest"
s3 cp "$latest" "s3://$R2_BUCKET/latest" --content-type text/plain

for feed in opkg apk; do
    comm -13 <(local_objects "$feed" | keys) <(remote_objects "$feed" | keys) \
        | while read -r key; do
            s3 rm "s3://$R2_BUCKET/$key"
        done
done

for feed in opkg apk; do
    if ! diff <(local_objects "$feed") <(remote_objects "$feed"); then
        echo "::error::R2 $feed/ does not hold exactly the feed $TAG built" >&2
        exit 1
    fi
done

echo "Published $TAG: $(local_objects opkg | wc -l) opkg and $(local_objects apk | wc -l) apk files."
