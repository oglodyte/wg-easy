ARG NODE_IMAGE=docker.io/library/node:24.19.0-alpine3.23@sha256:244cc2b53f46f9e876304391d17682b0ddae9ac33491f4857e25e35a36ba7995
FROM ${NODE_IMAGE} AS build
WORKDIR /app

ARG AMNEZIAWG_GO_VERSION=v3.0.20260805
ARG AMNEZIAWG_GO_COMMIT=08d68cdae27762c3e07f36bbb12d2bad32f81926
ARG AMNEZIAWG_TOOLS_VERSION=v3.0.20260805
ARG AMNEZIAWG_TOOLS_COMMIT=9f70177d204d5be66c5b043518a57b7d62b3f9d1
ARG PNPM_VERSION=11.21.0

# Install the repository-declared package manager without a moving Corepack update.
RUN corepack enable pnpm && corepack prepare "pnpm@${PNPM_VERSION}" --activate

# Copy Web UI
COPY src/package.json src/pnpm-lock.yaml src/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

# Build UI
COPY src ./
RUN pnpm build

# Build amneziawg-tools
COPY staging/phase0/client-lab/patch-awg-quick.sh /tmp/patch-awg-quick.sh
RUN apk add linux-headers build-base go git && \
    git clone --depth 1 --branch "${AMNEZIAWG_TOOLS_VERSION}" https://github.com/amnezia-vpn/amneziawg-tools.git && \
    git clone --depth 1 --branch "${AMNEZIAWG_GO_VERSION}" https://github.com/amnezia-vpn/amneziawg-go && \
    test "$(git -C amneziawg-tools rev-parse HEAD)" = "${AMNEZIAWG_TOOLS_COMMIT}" && \
    test "$(git -C amneziawg-go rev-parse HEAD)" = "${AMNEZIAWG_GO_COMMIT}" && \
    sh /tmp/patch-awg-quick.sh amneziawg-tools/src/wg-quick/linux.bash && \
    cd amneziawg-go && \
    make && \
    cd ../amneziawg-tools/src && \
    make && \
    sed -i 's|\[\[ $proto == -4 \]\] && cmd sysctl -q net\.ipv4\.conf\.all\.src_valid_mark=1|[[ $proto == -4 ]] \&\& [[ $(sysctl -n net.ipv4.conf.all.src_valid_mark) != 1 ]] \&\& cmd sysctl -q net.ipv4.conf.all.src_valid_mark=1|' ./wg-quick/linux.bash

# Copy build result to a new image.
# This saves a lot of disk space.
FROM ${NODE_IMAGE}
WORKDIR /app

HEALTHCHECK --interval=1m --timeout=5s --retries=3 CMD /usr/bin/timeout 5s /usr/bin/wget -q -O /dev/null http://127.0.0.1:51821/api/health

# Copy build
COPY --from=build /app/.output /app
# Copy migrations
COPY --from=build /app/server/database/migrations /app/server/database/migrations
# cli
COPY --from=build /app/cli/cli.sh /usr/local/bin/cli
RUN chmod +x /usr/local/bin/cli
# Copy amneziawg-go
COPY --from=build /app/amneziawg-go/amneziawg-go /usr/bin/amneziawg-go
RUN chmod +x /usr/bin/amneziawg-go
# Copy amneziawg-tools
COPY --from=build /app/amneziawg-tools/src/wg /usr/bin/awg
COPY --from=build /app/amneziawg-tools/src/wg-quick/linux.bash /usr/bin/awg-quick
RUN chmod +x /usr/bin/awg /usr/bin/awg-quick

# Install Linux packages
RUN apk add --no-cache \
    dpkg \
    dumb-init \
    iptables \
    ip6tables \
    iproute2 \
    nftables \
    kmod \
    iptables-legacy \
    wireguard-go \
    wireguard-tools

RUN mkdir -p /etc/amnezia
RUN ln -s /etc/wireguard /etc/amnezia/amneziawg

# Use iptables-legacy
RUN update-alternatives --install /usr/sbin/iptables iptables /usr/sbin/iptables-legacy 10 --slave /usr/sbin/iptables-restore iptables-restore /usr/sbin/iptables-legacy-restore --slave /usr/sbin/iptables-save iptables-save /usr/sbin/iptables-legacy-save
RUN update-alternatives --install /usr/sbin/ip6tables ip6tables /usr/sbin/ip6tables-legacy 10 --slave /usr/sbin/ip6tables-restore ip6tables-restore /usr/sbin/ip6tables-legacy-restore --slave /usr/sbin/ip6tables-save ip6tables-save /usr/sbin/ip6tables-legacy-save

# Set Environment
ENV DEBUG=Server,WireGuard,Database,CMD,Firewall
ENV PORT=51821
ENV HOST=0.0.0.0
ENV INSECURE=false
ENV INIT_ENABLED=false
ENV DISABLE_IPV6=false

LABEL org.opencontainers.image.source=https://github.com/wg-easy/wg-easy
LABEL org.opencontainers.image.node.version="24.19.0"
LABEL org.opencontainers.image.amneziawg-go.revision="08d68cdae27762c3e07f36bbb12d2bad32f81926"
LABEL org.opencontainers.image.amneziawg-tools.revision="9f70177d204d5be66c5b043518a57b7d62b3f9d1"

# Run Web UI
CMD ["/usr/bin/dumb-init", "node", "server/index.mjs"]
