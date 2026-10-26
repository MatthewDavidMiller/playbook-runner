#!/bin/bash
# The Rust gate: formatting, the first-party dependency graph, the unsafe
# allowlist, the toolchain pin, clippy, and the test suites.
#
# Usage: ./scripts/check-rust.sh   (run through scripts/toolbox.sh)

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

for tool in cargo rustfmt; do
    command -v "${tool}" >/dev/null || { echo "ERROR: ${tool} is required" >&2; exit 1; }
done

echo "== toolchain pin"
pinned="$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)"
installer="$(sed -n 's/^RUST_STABLE="\(.*\)"$/\1/p' scripts/install-rust.sh)"
workspace="$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' Cargo.toml)"
if [[ -z "${pinned}" || "${pinned}" != "${installer}" || "${pinned}" != "${workspace}" ]]; then
    echo "ERROR: rust-toolchain.toml (${pinned}), install-rust.sh (${installer})," \
        "and Cargo.toml rust-version (${workspace}) must name one release" >&2
    exit 1
fi

echo "== rustfmt"
cargo fmt --all -- --check

echo "== workspace-only dependency graph"
cargo generate-lockfile --offline >/dev/null
if grep -q '^source = ' Cargo.lock; then
    echo "ERROR: Cargo.lock names a package from outside the workspace:" >&2
    grep -B2 '^source = ' Cargo.lock >&2
    exit 1
fi
members="$(sed -n 's/^name = "\(.*\)"$/\1/p' Cargo.lock | sort)"
expected="$(find crates -mindepth 2 -maxdepth 2 -name Cargo.toml -exec \
    awk -F'"' '/^\[/ { in_package = ($0 == "[package]") } in_package && /^name = / { print $2 }' {} \; |
    sort)"
if [[ "${members}" != "${expected}" ]]; then
    echo "ERROR: Cargo.lock packages differ from the workspace members" >&2
    diff <(echo "${expected}") <(echo "${members}") >&2 || true
    exit 1
fi

echo "== unsafe allowlist"
UNSAFE_CRATES=(pr-sys)
for manifest in crates/*/Cargo.toml; do
    dir="$(dirname "${manifest}")"
    name="$(basename "${dir}")"
    allowed=false
    for a in "${UNSAFE_CRATES[@]}"; do [[ "${name}" == "${a}" ]] && allowed=true; done
    [[ "${allowed}" == true ]] && continue
    while IFS= read -r root; do
        grep -q '^#!\[forbid(unsafe_code)\]' "${root}" || {
            echo "ERROR: ${root} must forbid unsafe_code" >&2
            exit 1
        }
    done < <(find "${dir}/src" -maxdepth 2 \( -name lib.rs -o -name main.rs -o -path '*/bin/*.rs' \))
done

echo "== clippy"
cargo clippy --workspace --all-targets --offline --locked -- -D warnings

echo "== tests"
cargo test --workspace --offline --locked
