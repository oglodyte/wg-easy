ARG ALPINE_IMAGE=docker.io/library/alpine@sha256:7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6
ARG GOLANG_IMAGE=docker.io/library/golang@sha256:65b4400aee0927412e9ed791a11893273a49d55df24841f7599660fb80dae464

FROM ${GOLANG_IMAGE} AS awg-go-build

ARG AMNEZIAWG_GO_COMMIT=9f5d948bc72cc554791cfe0fb91527e4acfb6b79

RUN apk add --no-cache \
    bash=5.2.37-r0 \
    build-base=0.5-r3 \
    ca-certificates=20260611-r0 \
    git=2.49.1-r0 \
    linux-headers=6.14.2-r0

RUN git clone https://github.com/amnezia-vpn/amneziawg-go.git /src/amneziawg-go && \
    git -C /src/amneziawg-go checkout --detach "${AMNEZIAWG_GO_COMMIT}" && \
    make -C /src/amneziawg-go

FROM ${ALPINE_IMAGE} AS awg-tools-build

ARG AMNEZIAWG_TOOLS_COMMIT=d09ecc38425082e472368dd2bf8c4c42d10cae03

RUN apk add --no-cache \
    bash=5.2.37-r0 \
    build-base=0.5-r3 \
    ca-certificates=20260611-r0 \
    git=2.49.1-r0 \
    linux-headers=6.14.2-r0

RUN git clone https://github.com/amnezia-vpn/amneziawg-tools.git /src/amneziawg-tools && \
    git -C /src/amneziawg-tools checkout --detach "${AMNEZIAWG_TOOLS_COMMIT}" && \
    make -C /src/amneziawg-tools/src

FROM ${ALPINE_IMAGE} AS vpn-base

RUN apk add --no-cache \
    bash=5.2.37-r0 \
    ca-certificates=20260611-r0 \
    curl=8.14.1-r3 \
    iproute2=6.15.0-r0 \
    iptables=1.8.11-r1 \
    jq=1.8.1-r0 \
    wireguard-tools=1.0.20250521-r0

COPY vpn-entrypoint.sh /usr/local/bin/vpn-entrypoint
RUN chmod 0755 /usr/local/bin/vpn-entrypoint

ENTRYPOINT ["/usr/local/bin/vpn-entrypoint"]

FROM vpn-base AS wg-client

ENV VPN_TOOL=wg
LABEL org.opencontainers.image.title="wg-easy Phase 0 generic WireGuard client"
LABEL org.opencontainers.image.description="Contains generic WireGuard tooling only; no AmneziaWG binaries"

FROM vpn-base AS awg-client

COPY --from=awg-go-build /src/amneziawg-go/amneziawg-go /usr/bin/amneziawg-go
COPY --from=awg-tools-build /src/amneziawg-tools/src/wg /usr/bin/awg
COPY --from=awg-tools-build /src/amneziawg-tools/src/wg-quick/linux.bash /usr/bin/awg-quick
RUN chmod 0755 /usr/bin/amneziawg-go /usr/bin/awg /usr/bin/awg-quick

ENV VPN_TOOL=awg
LABEL org.opencontainers.image.title="wg-easy Phase 0 pinned AmneziaWG client"
LABEL org.opencontainers.image.amneziawg-go.revision="9f5d948bc72cc554791cfe0fb91527e4acfb6b79"
LABEL org.opencontainers.image.amneziawg-tools.revision="d09ecc38425082e472368dd2bf8c4c42d10cae03"

FROM ${ALPINE_IMAGE} AS traffic-sink

RUN apk add --no-cache \
    iproute2=6.15.0-r0 \
    python3=3.12.13-r0

COPY sink-entrypoint.sh /usr/local/bin/sink-entrypoint
COPY sink.py /usr/local/lib/wg-easy-lab/sink.py
RUN chmod 0755 /usr/local/bin/sink-entrypoint

ENTRYPOINT ["/usr/local/bin/sink-entrypoint"]
LABEL org.opencontainers.image.title="wg-easy Phase 0 traffic sink"
