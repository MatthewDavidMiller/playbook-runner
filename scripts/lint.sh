#!/bin/bash
# Lint the shell scripts and the git hooks.
#
# Usage: ./scripts/lint.sh   (run through scripts/toolbox.sh)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

echo "== shellcheck"
mapfile -t scripts < <(git ls-files --cached --others --exclude-standard -- '*.sh' '.githooks/*')
shellcheck --external-sources "${scripts[@]}"
