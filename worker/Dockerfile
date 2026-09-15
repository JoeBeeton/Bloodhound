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
# Checksum-verified, not just version-pinned - a security review noted this was fetched via curl
# with no signature/checksum check at all, unlike zgrab2 below (go install gets module-proxy
# checksum verification for free). ProjectDiscovery publishes a sha256 checksums file alongside
# every release; verified against it here before the archive is ever unzipped.
ARG SUBFINDER_VERSION=2.15.0
RUN curl -fsSL -O \
      "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" \
    && curl -fsSL -o subfinder_checksums.txt \
      "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_checksums.txt" \
    && grep " subfinder_${SUBFINDER_VERSION}_linux_amd64.zip\$" subfinder_checksums.txt | sha256sum -c - \
    && unzip "subfinder_${SUBFINDER_VERSION}_linux_amd64.zip" subfinder \
    && chmod +x subfinder

# katana (ProjectDiscovery, MIT - license-checked the same way as nuclei below) - same
# prebuilt-binary, checksum-verified pattern as subfinder above. A second, active subdomain
# source alongside crt.sh/subfinder's passive lookups: crawls the target's own site and parses
# every fetched JS file for endpoint-shaped strings via -jc (see KatanaCliSource), catching
# hostnames a company's own frontend code references that never got a public CT-logged cert and
# aren't a guessable wordlist entry - a different discovery angle than either existing source
# structurally can cover. Version pinned; bump deliberately, don't float latest.
FROM ghcr.io/graalvm/jdk-community:21 AS katana
WORKDIR /tmp/katana
RUN microdnf install -y unzip curl ca-certificates && microdnf clean all
ARG KATANA_VERSION=1.7.0
RUN curl -fsSL -O \
      "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_amd64.zip" \
    && curl -fsSL -o katana_checksums.txt \
      "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana-${KATANA_VERSION}-checksums.txt" \
    && grep " katana_${KATANA_VERSION}_linux_amd64.zip\$" katana_checksums.txt | sha256sum -c - \
    && unzip "katana_${KATANA_VERSION}_linux_amd64.zip" katana \
    && chmod +x katana

# naabu (ProjectDiscovery, MIT) - same prebuilt-binary pattern as subfinder
# above. modules/portscan's Tier 2 full-port-range discovery tool - see
# NaabuFetcher/DeepPortScanModule (Tier 1's light scan needed no external
# binary at all - it's a plain java.net.Socket connect sweep).
FROM ghcr.io/graalvm/jdk-community:21 AS naabu
WORKDIR /tmp/naabu
RUN microdnf install -y unzip curl ca-certificates && microdnf clean all
# Checksum-verified - same reasoning as subfinder above. naabu's checksums file (unlike
# subfinder's/nuclei's) doesn't embed the version in its filename - confirmed against the actual
# release assets, not guessed.
ARG NAABU_VERSION=2.6.1
RUN curl -fsSL -O \
      "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_amd64.zip" \
    && curl -fsSL -o naabu_checksums.txt \
      "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu-checksums.txt" \
    && grep " naabu_${NAABU_VERSION}_linux_amd64.zip\$" naabu_checksums.txt | sha256sum -c - \
    && unzip "naabu_${NAABU_VERSION}_linux_amd64.zip" naabu \
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
# Checksum-verified - same reasoning as subfinder above.
ARG NUCLEI_VERSION=3.11.1
RUN curl -fsSL -O \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && curl -fsSL -o nuclei_checksums.txt \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_checksums.txt" \
    && grep " nuclei_${NUCLEI_VERSION}_linux_amd64.zip\$" nuclei_checksums.txt | sha256sum -c - \
    && unzip "nuclei_${NUCLEI_VERSION}_linux_amd64.zip" nuclei \
    && chmod +x nuclei
#
# -disable-update-check must NOT be combined with -update-templates here -
# confirmed empirically (silently does nothing, no error, no directory
# created) - that flag is only appropriate for the runtime scan invocation
# (see NucleiFetcher) to skip nuclei's own update check on every scan, not
# for this one-time template-install step.
#
# The chmod matters: nuclei writes the corpus with 0700 directories, so after the non-root
# USER switch below the worker's uid 1000 couldn't read a single template. nuclei then died
# with "FTL Could not run nuclei: no templates provided for scan" - to stderr, which
# NucleiFetcher used to discard - and every NUCLEI_SCAN job "completed" with 0 findings for
# two weeks before the live data (hosts with confirmed deprecated TLS, zero nuclei hits)
# gave it away. Done in the same layer as the download so the final image doesn't carry
# the corpus twice.
RUN ./nuclei -update-templates -ud /tmp/nuclei-templates \
    && chmod -R a+rX /tmp/nuclei-templates

FROM ghcr.io/graalvm/jdk-community:21
WORKDIR /app

RUN microdnf install -y ca-certificates && microdnf clean all

COPY --from=subfinder /tmp/subfinder/subfinder /usr/local/bin/subfinder
COPY --from=katana /tmp/katana/katana /usr/local/bin/katana
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

COPY --from=build --chown=1000:1000 /project/worker/build/libs/worker.jar app.jar
# A container-hardening review found this (and central-server's/webui's) had no USER directive -
# ran as root by default. worker is the highest-value target for this fix specifically: it
# bundles subfinder/naabu/zgrab2/nuclei, all of which parse untrusted responses from real external
# scan targets, so a memory-safety bug in any of them processing attacker-controlled data would
# otherwise execute as root. HOME=/tmp because these are real third-party CLI tools with their own
# assumptions about a writable home directory for cache/config (zgrab2's own blocklist-file
# default lookup above is a documented instance of exactly this) - the numeric-UID-only user below
# has no /etc/passwd entry and so no real home directory; /tmp is reliably world-writable
# regardless of which UID owns it, giving any tool that wants to write somewhere a valid target
# without needing to special-case each one the way zgrab2's blocklist already had to be.
ENV HOME=/tmp
USER 1000:1000
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "app.jar"]
