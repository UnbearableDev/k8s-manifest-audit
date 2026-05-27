#!/usr/bin/env bash
set -euo pipefail
expected=$(cat Dockerfile.sha256)
actual=$(sha256sum Dockerfile | awk '{print $1}')
if [[ "$expected" != "$actual" ]]; then
  echo "ERROR: Dockerfile hash mismatch — expected $expected got $actual" >&2
  echo "If this change is intentional, run: sha256sum Dockerfile | awk '{print \$1}' > Dockerfile.sha256" >&2
  exit 1
fi
