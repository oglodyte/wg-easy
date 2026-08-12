ARG NODE_IMAGE=docker.io/library/node:22.22.0-alpine3.23@sha256:e4bf2a82ad0a4037d28035ae71529873c069b13eb0455466ae0bc13363826e34
FROM ${NODE_IMAGE} AS build
WORKDIR /app

ARG AMNEZIAWG_GO_COMMIT=9f5d948bc72cc554791cfe0fb91527e4acfb6b79
ARG AMNEZIAWG_TOOLS_COMMIT=d09ecc38425082e472368dd2bf8c4c42d10cae03
ARG PNPM_VERSION=11.15.1

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
    git clone https://github.com/amnezia-vpn/amneziawg-tools.git && \
    git clone https://github.com/amnezia-vpn/amneziawg-go && \
    git -C amneziawg-tools checkout --detach "${AMNEZIAWG_TOOLS_COMMIT}" && \
    git -C amneziawg-go checkout --detach "${AMNEZIAWG_GO_COMMIT}" && \
    sh /tmp/patch-awg-quick.sh amneziawg-tools/src/wg-quick/linux.bash && \
    cd amneziawg-go && \
    make && \
    cd ../amneziawg-tools/src && \
    make && \
    sed -i 's|\[\[ $proto == -4 \]\] && cmd sysctl -q net\.ipv4\.conf\.all\.src_valid_mark=1|[[ $proto == -4 ]] \&\& [[ $(sysctl -n net.ipv4.conf.all.src_valid_mark) != 1 ]] \&\& cmd sysctl -q net.ipv4.conf.all.src_valid_mark=1|' ./wg-quick/linux.bash

FROM ${NODE_IMAGE} AS build-libsql
WORKDIR /app
ARG LIBSQL_VERSION=0.5.29
RUN npm install --no-save --omit=dev --package-lock=false "libsql@${LIBSQL_VERSION}"

# Copy build result to a new image.
# This saves a lot of disk space.
FROM ${NODE_IMAGE}
WORKDIR /app

HEALTHCHECK --interval=1m --timeout=5s --retries=3 CMD /usr/bin/timeout 5s /usr/bin/wget -q -O /dev/null http://127.0.0.1:51821/api/health

# Copy build
COPY --from=build /app/.output /app
# Copy migrations
COPY --from=build /app/server/database/migrations /app/server/database/migrations
# libsql (https://github.com/nitrojs/nitro/issues/3328)
COPY --from=build-libsql /app/node_modules /app/server/node_modules

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
    wireguard-tools && \
    sed -i 's|\[\[ $proto == -4 \]\] && cmd sysctl -q net\.ipv4\.conf\.all\.src_valid_mark=1|[[ $proto == -4 ]] \&\& [[ $(sysctl -n net.ipv4.conf.all.src_valid_mark) != 1 ]] \&\& cmd sysctl -q net.ipv4.conf.all.src_valid_mark=1|' /usr/bin/wg-quick

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
LABEL org.opencontainers.image.node.version="22.22.0"
LABEL org.opencontainers.image.libsql.version="0.5.29"
LABEL org.opencontainers.image.amneziawg-go.revision="9f5d948bc72cc554791cfe0fb91527e4acfb6b79"
LABEL org.opencontainers.image.amneziawg-tools.revision="d09ecc38425082e472368dd2bf8c4c42d10cae03"

# Run Web UI
CMD ["/usr/bin/dumb-init", "node", "server/index.mjs"]
