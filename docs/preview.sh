#!/bin/bash
set -euo pipefail

PORT="${1:-8080}"

THIS_DIR="$(cd "$(dirname "$(readlink "$0" || echo "$0")")"; pwd -P)"

docker rm doc-preview > /dev/null 2>&1 || true
docker run -p ${PORT}:8080 -it --name doc-preview \
    -v "$THIS_DIR"/directory.json:/app/docs/.vitepress/config/directory.json \
    -v "$THIS_DIR"/en_US:/app/docs/en/latest \
    -v "$THIS_DIR"/zh_CN:/app/docs/zh/latest \
    -e DOCS_TYPE=nanomq \
    -e VERSION=latest \
ghcr.io/emqx/emqx-io-docs-next:latest
