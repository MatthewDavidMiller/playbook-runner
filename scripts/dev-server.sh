#!/bin/bash
# Run playbook-runner locally for manual testing, at http://127.0.0.1:8080.
#
# Usage: make dev   (or ./scripts/dev-server.sh)
#
# State lives in ./data (git-ignored): a development master key generated on
# first use, the admin password, and every record. Delete ./data to start
# over. The setup token is printed when the server starts.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA="${PROJECT_ROOT}/data"
PORT="${PR_DEV_PORT:-8080}"

mkdir -p "${DATA}/state"
chmod 700 "${DATA}" "${DATA}/state"

export PR_LISTEN="0.0.0.0:${PORT}"
export PR_DATA_DIR="${DATA}/state"
export PR_WORK_DIR="${DATA}/work"
export PR_MASTER_KEY_FILE="${DATA}/dev.key"
export PR_SECURE_COOKIES=false
export PR_TIMEZONE="${PR_TIMEZONE:-America/New_York}"

# shellcheck disable=SC2016 # expanded inside the toolbox, not here
exec "${PROJECT_ROOT}/scripts/toolbox.sh" --publish "${PORT}" bash -c '
    set -euo pipefail
    cargo build -q -p pr-web --bin playbook-runner
    if [[ ! -s "${PR_MASTER_KEY_FILE}" ]]; then
        (umask 077 && target/debug/playbook-runner gen-key > "${PR_MASTER_KEY_FILE}")
        echo "Generated a development master key in data/dev.key"
    fi
    exec target/debug/playbook-runner serve
'
