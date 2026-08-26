# Build context is the repo root (multi-module Gradle build). settings.gradle.kts
# includes all four modules, so Gradle needs every project directory present
# to evaluate the build even though we only assemble worker's jar here.
FROM gradle:8.12-jdk21 AS build
WORKDIR /project
COPY settings.gradle.kts build.gradle.kts ./
COPY gradle ./gradle
COPY gradlew ./
COPY bloodhound-common ./bloodhound-common
COPY worker ./worker
COPY central-server/build.gradle.kts ./central-server/build.gradle.kts
COPY webui/backend/build.gradle.kts ./webui/backend/build.gradle.kts
RUN ./gradlew :worker:bootJar --no-daemon -x test

# subfinder (ProjectDiscovery) - a static Linux amd64 binary, downloaded and
# unzipped here rather than built, matching how the runtime stage below stays
# minimal. Version pinned; bump deliberately, don't float latest. amass was
# evaluated too but its v5 CLI has moved to a more involved engine/config
# model with no confirmed simple passive-only invocation - not worth the
# added build complexity for marginal gain over crt.sh + subfinder, so it's
# left out of Phase 1 (documented deviation from the milestone brief, which
# left amass as a judgment call).
FROM ghcr.io/graalvm/jdk-community:21 AS subfinder
WORKDIR /tmp/subfinder
RUN microdnf install -y unzip curl ca-certificates && microdnf clean all
ARG SUBFINDER_VERSION=2.15.0
RUN curl -fsSL -o subfinder.zip \
      "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" \
    && unzip subfinder.zip subfinder \
    && chmod +x subfinder

# naabu (ProjectDiscovery, MIT) - same prebuilt-binary pattern as subfinder
# above. modules/portscan's Tier 2 full-port-range discovery tool - see
# NaabuFetcher/DeepPortScanModule (Tier 1's light scan needed no external
# binary at all - it's a plain java.net.Socket connect sweep).
FROM ghcr.io/graalvm/jdk-community:21 AS naabu
WORKDIR /tmp/naabu
RUN microdnf install -y unzip curl ca-certificates && microdnf clean all
ARG NAABU_VERSION=2.6.1
RUN curl -fsSL -o naabu.zip \
      "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_amd64.zip" \
    && unzip naabu.zip naabu \
    && chmod +x naabu

# zgrab2 (ZMap project, Apache-2.0) - best-effort service identification on
# whatever naabu finds open (see Zgrab2Fetcher/BannerDecisionLogic). Built
# from source, not downloaded, because upstream doesn't publish prebuilt
# release binaries. Version pinned to the zgrab2 git tag; bump deliberately,
# don't float latest.
FROM golang:1.24-bookworm AS zgrab2
ARG ZGRAB2_VERSION=v1.0.0
RUN go install "github.com/zmap/zgrab2/cmd/zgrab2@${ZGRAB2_VERSION}"

# nuclei (ProjectDiscovery, MIT) - Tier 2 template-based vulnerability
# scanning, see NucleiFetcher/NucleiActiveScanModule. Same prebuilt-binary
# pattern as subfinder/naabu above. Both the engine and the separately
# licensed nuclei-templates corpus baked in below were license-checked
# against each repo's actual license (LICENSE.md / GitHub-reported license)
# before adding - both MIT.
#
# Templates are fetched and pinned into the image at build time, not
# fetched/updated at scan time - reproducible builds, and no runtime
# dependency on GitHub being reachable mid-scan (NucleiFetcher passes
# -disable-update-check and points -t at the exact directory baked in here).
FROM ghcr.io/graalvm/jdk-community:21 AS nuclei
WORKDIR /tmp/nuclei
RUN microdnf install -y unzip curl ca-certificates && microdnf clean all
ARG NUCLEI_VERSION=3.11.1
RUN curl -fsSL -o nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip nuclei.zip nuclei \
    && chmod +x nuclei
#
# -disable-update-check must NOT be combined with -update-templates here -
# confirmed empirically (silently does nothing, no error, no directory
# created) - that flag is only appropriate for the runtime scan invocation
# (see NucleiFetcher) to skip nuclei's own update check on every scan, not
# for this one-time template-install step.
RUN ./nuclei -update-templates -ud /tmp/nuclei-templates

FROM ghcr.io/graalvm/jdk-community:21
WORKDIR /app

RUN microdnf install -y ca-certificates && microdnf clean all

COPY --from=subfinder /tmp/subfinder/subfinder /usr/local/bin/subfinder
COPY --from=naabu /tmp/naabu/naabu /usr/local/bin/naabu
COPY --from=zgrab2 /go/bin/zgrab2 /usr/local/bin/zgrab2
COPY --from=nuclei /tmp/nuclei/nuclei /usr/local/bin/nuclei
COPY --from=nuclei /tmp/nuclei-templates /opt/nuclei-templates

# zgrab2 refuses to start without a blocklist file and defaults to looking
# for one under $HOME/.config/zgrab2/ - there's no such thing in this image
# (confirmed for real: it's a hard fatal error, not a skipped check). An
# empty file baked in and referenced explicitly via -b in Zgrab2Fetcher is
# the whole fix - Bloodhound has its own SSRF/private-range guard
# (SafeAddressValidator) upstream of every scan module already, so zgrab2's
# own blocklist has nothing to add here.
RUN touch /etc/zgrab2-blocklist.conf

COPY --from=build /project/worker/build/libs/worker.jar app.jar
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "app.jar"]
