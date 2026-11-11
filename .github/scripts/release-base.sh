#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# release-base.sh TAG COMMIT prints the branch the tag may be published from (RELEASING.md),
# or refuses. A minor version (vX.Y.0 and its pre-releases) comes from main only; a patch comes from
# its own branch release/X.Y only, because main holds functions of the next minor version.
# Reads the remote-tracking branches of the current repository; tested by internal/releasebase.
set -euo pipefail

tag=$1
commit=$2

refuse() {
  echo "::error::$1" >&2
  exit 1
}

# on BRANCH tells whether the commit is on the remote-tracking branch; a branch that does not
# exist has no commits.
on() {
  git rev-parse --quiet --verify "refs/remotes/origin/$1^{commit}" > /dev/null &&
    git merge-base --is-ancestor "$commit" "refs/remotes/origin/$1"
}

if ! [[ "$tag" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)(-(alpha|rc)\.[0-9]+)?$ ]]; then
  refuse "tag $tag is neither vX.Y.Z nor vX.Y.Z-alpha.N nor vX.Y.Z-rc.N"
fi
minor="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
patch="${BASH_REMATCH[3]}"

if [ "$patch" = 0 ]; then
  on main || refuse "$tag is a minor version and points to a commit that is not on main"
  echo main
else
  on "release/$minor" || refuse "$tag is a patch and points to a commit that is not on release/$minor"
  echo "release/$minor"
fi
