#!/usr/bin/env bash
set -euxo pipefail
rm -rf release
mkdir -p release
# build for all common arch and platforms
for supported_os in darwin linux windows
do
    for supported_arch in amd64 arm64
    do
        file_ext=""
        if [[ "$supported_os" == "windows" ]]; then
            file_ext=".exe"
        fi
        output_name="nucunlocker-${supported_os}-${supported_arch}${file_ext}"
        # Static build, CGO_ENABLED=0
        CGO_ENABLED=0 GOOS="$supported_os" GOARCH="$supported_arch" go build -o "release/$output_name" main.go
    done
done
pushd release
sha256sum nucunlocker-* |tee nucunlocker.sha256sums
gpg --armor --output nucunlocker.sha256sums.asc --detach-sign nucunlocker.sha256sums
gpg --verify nucunlocker.sha256sums.asc nucunlocker.sha256sums

echo done
