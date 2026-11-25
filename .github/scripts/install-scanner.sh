#!/usr/bin/env bash
set -euo pipefail

case "$1" in
  actionlint)
    release=rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz
    digest=8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8
    ;;
  gitleaks)
    release=gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz
    digest=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
    ;;
  trivy)
    release=aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_Linux-64bit.tar.gz
    digest=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
    ;;
  syft)
    release=anchore/syft/releases/download/v1.57.2/syft_1.57.2_linux_amd64.tar.gz
    digest=ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b
    ;;
  *)
    echo "Unknown scanner: $1" >&2
    exit 2
    ;;
esac

mkdir -p "$RUNNER_TEMP/scanners"
archive=$(mktemp)
trap 'rm -f -- "$archive"' EXIT
curl --fail --silent --show-error --location --retry 3 "https://github.com/$release" -o "$archive"
printf '%s  %s\n' "$digest" "$archive" | sha256sum --check --status
tar -xzf "$archive" -C "$RUNNER_TEMP/scanners" "$1"
