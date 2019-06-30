#!/usr/bin/env bash

# For Travis, so that git describe gives something useful
git fetch --tags .

export TERMSHARK_GIT_DESCRIBE="$(git describe --tags HEAD)"

curl -sL https://git.io/goreleaser > /tmp/goreleaser.sh
bash /tmp/goreleaser.sh --snapshot --skip-sign
