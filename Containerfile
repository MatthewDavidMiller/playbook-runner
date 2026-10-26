# The playbook-runner runtime image.
#
# Both stages start from the official Alpine image pinned by digest -- the
# same release and digest as the toolbox (tools/toolbox/Dockerfile) -- so the
# binary is built against the musl and libcrypto it ships with. The builder
# installs the repository-pinned Rust toolchain through the same
# checksum-verified installer the gates use, rather than trusting a second
# base image for the compiler.
#
# The binary is fully static (musl, static-pie, libcrypto linked in), so the
# runtime stage carries no OpenSSL package for it. What the runtime does carry
# is what a run executes: git, the OpenSSH client and agent, Python with a
# hash-pinned ansible-core, the pinned collections, and tzdata.
#
# Run it read-only, as the non-root user it declares, with the master key as
# a Podman secret and a tmpfs work directory; see docs/DEPLOYMENT.md.

ARG ALPINE_DIGEST=sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40

FROM docker.io/library/alpine:3.23.5@${ALPINE_DIGEST} AS build

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

RUN apk add --no-cache bash build-base curl musl-dev openssl-dev openssl-libs-static

ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH="/opt/cargo/bin:${PATH}"
COPY scripts/install-rust.sh /tmp/install-rust.sh
RUN /tmp/install-rust.sh --build-only

WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .cargo .cargo
COPY crates crates

# static-pie against musl with libcrypto linked in; RUSTFLAGS replaces the
# development crt-static=off setting in .cargo/config.toml.
RUN PR_OPENSSL_STATIC=1 \
    RUSTFLAGS="-C target-feature=+crt-static -C relocation-model=pie" \
    cargo build --release --locked --offline --target x86_64-unknown-linux-musl \
        -p pr-web --bin playbook-runner \
    && install -m 0755 target/x86_64-unknown-linux-musl/release/playbook-runner /playbook-runner


FROM docker.io/library/alpine:3.23.5@${ALPINE_DIGEST}

SHELL ["/bin/ash", "-eo", "pipefail", "-c"]

# ca-certificates for https git remotes; openssh-client for ssh, ssh-agent,
# and ssh-add; tzdata for PR_TIMEZONE. pip only bootstraps the venv: both
# the system package and the venv's own copy are removed once ansible-core
# is installed, so nothing in the image can install more Python code.
RUN apk add --no-cache ca-certificates git openssh-client python3 tzdata \
    && apk add --no-cache --virtual .pip py3-pip

COPY runtime/requirements.txt runtime/collections.yml /tmp/runtime/
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --no-deps --require-hashes \
        --only-binary=:all: -r /tmp/runtime/requirements.txt \
    && /opt/venv/bin/ansible-galaxy collection install \
        -r /tmp/runtime/collections.yml -p /usr/share/ansible/collections \
    && /opt/venv/bin/python -m pip uninstall -y -q pip \
    && apk del .pip \
    && rm -rf /tmp/runtime /root/.ansible /root/.cache

COPY --from=build /playbook-runner /usr/local/bin/playbook-runner

# The user's home is the tmpfs work directory, not the data volume: ansible
# resolves ~ for tasks that run on the controller itself (connection: local,
# delegate_to: localhost) from the passwd entry, and its temporary files
# belong on the tmpfs with everything else a run writes.
RUN addgroup -S -g 10001 runner \
    && adduser -S -D -H -u 10001 -G runner -h /run/playbook-runner -s /sbin/nologin runner \
    && install -d -m 0700 -o runner -g runner /var/lib/playbook-runner /run/playbook-runner

ENV PATH="/opt/venv/bin:/usr/local/bin:/usr/bin:/bin" \
    PR_LISTEN=0.0.0.0:8080 \
    PR_DATA_DIR=/var/lib/playbook-runner \
    PR_WORK_DIR=/run/playbook-runner \
    HOME=/run/playbook-runner

USER 10001:10001
WORKDIR /var/lib/playbook-runner
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/usr/local/bin/playbook-runner", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/playbook-runner"]
CMD ["serve"]
