#!/bin/bash
# Build the runtime image and test it the way VM1 runs it.
#
# Usage: make test-image   (runs on the host; needs rootless Podman)
#
# 1. Builds the image from the Containerfile.
# 2. Starts it with VM1's flags -- read-only root, every capability dropped,
#    no-new-privileges, a memory cap with no swap, a pids limit, noexec
#    tmpfs work and /tmp, and the master key as a Podman secret -- and checks
#    it becomes healthy, runs as uid 10001, and prints a setup token.
# 3. Builds the end-to-end test binaries statically and runs them inside the
#    same image under the same flags, so the real run engine is exercised
#    against the image's own git, OpenSSH, Python, and ansible-core.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"
IMAGE="localhost/playbook-runner:test"
NAME="pr-image-test-$$"
SECRET="pr-image-test-key-$$"
VOLUME="pr-image-test-data-$$"
PORT="${PR_TEST_PORT:-18080}"
WORK="$(mktemp -d)"

cleanup() {
    podman rm -f "${NAME}" >/dev/null 2>&1 || true
    podman secret rm "${SECRET}" >/dev/null 2>&1 || true
    podman volume rm -f "${VOLUME}" >/dev/null 2>&1 || true
    rm -rf "${WORK}"
}
trap cleanup EXIT

# The flags roles/playbook_runner uses on VM1.
# shellcheck disable=SC2054 # the commas are inside mount option lists
SECURITY=(
    --read-only
    --cap-drop=ALL
    --security-opt=no-new-privileges:true
    --memory=512m
    --memory-swap=512m
    --pids-limit=300
    --mount type=tmpfs,destination=/run/playbook-runner,tmpfs-size=256m,tmpfs-mode=0700,U=true,noexec,nosuid,nodev
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777
)

echo "== build image"
podman build --format docker --platform linux/amd64 -q -f Containerfile -t "${IMAGE}" . >/dev/null

echo "== static binary"
podman run --rm --entrypoint sh "${IMAGE}" -c \
    'test "$(head -c 4 /usr/local/bin/playbook-runner | od -An -c | tr -d " ")" = "177ELF"' 

echo "== smoke: start with VM1 flags"
(umask 077 && podman run --rm --entrypoint /usr/local/bin/playbook-runner "${IMAGE}" gen-key > "${WORK}/key")
podman secret create "${SECRET}" "${WORK}/key" >/dev/null
podman run -d --name "${NAME}" "${SECURITY[@]}" \
    --secret "${SECRET},target=/run/secrets/playbook_runner_master_key,uid=10001,gid=10001,mode=0400" \
    -v "${VOLUME}:/var/lib/playbook-runner" \
    -e PR_TIMEZONE=America/New_York \
    -p "127.0.0.1:${PORT}:8080" \
    "${IMAGE}" >/dev/null
for _ in $(seq 1 30); do
    podman exec "${NAME}" playbook-runner healthcheck 2>/dev/null && break
    sleep 1
done
podman exec "${NAME}" playbook-runner healthcheck
[[ "$(podman exec "${NAME}" id -u)" == 10001 ]] || { echo "FAIL: not uid 10001" >&2; exit 1; }
podman logs "${NAME}" 2>&1 | grep -q "setup token" || { echo "FAIL: no setup token logged" >&2; exit 1; }
curl -fsS "http://127.0.0.1:${PORT}/setup" | grep -q "Create the admin password" \
    || { echo "FAIL: setup page not served" >&2; exit 1; }
if podman exec "${NAME}" sh -c 'touch /usr/local/bin/x' 2>/dev/null; then
    echo "FAIL: the root filesystem is writable" >&2
    exit 1
fi
podman rm -f "${NAME}" >/dev/null

echo "== end-to-end tests inside the image"
./scripts/toolbox.sh env PR_OPENSSL_STATIC=1 \
    RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=pie" \
    cargo test --release --locked --offline --no-run -q \
    --target x86_64-unknown-linux-musl --target-dir target/image-tests \
    -p pr-runner -p pr-web --test run --test web
mkdir -p "${WORK}/tests"
for t in run web; do
    bin="$(find target/image-tests/x86_64-unknown-linux-musl/release/deps -maxdepth 1 -type f \
        -name "${t}-*" ! -name '*.d' -printf '%T@ %p\n' | sort -n | tail -1 | cut -d' ' -f2)"
    [[ -n "${bin}" ]] || { echo "FAIL: no ${t} test binary" >&2; exit 1; }
    cp "${bin}" "${WORK}/tests/${t}"
done
chmod -R a+rX "${WORK}/tests"
for t in run web; do
    echo "-- ${t}"
    podman run --rm "${SECURITY[@]}" -v "${WORK}/tests:/tests:ro,Z" \
        --entrypoint "/tests/${t}" "${IMAGE}" --test-threads=1 -q
done
echo "Image checks passed."
