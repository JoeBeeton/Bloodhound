# Build context is the repo root (multi-module Gradle build). settings.gradle.kts
# includes all four modules, so Gradle needs every project directory present
# to evaluate the build even though we only assemble central-server's jar here.
# Pinned to an exact patch release: the previous floating ghcr.io/graalvm/jdk-community:21 tag had
# silently stopped at 21.0.2 (Jan 2024) when GraalVM Community dropped JDK 21 updates.
ARG JDK_IMAGE=eclipse-temurin:25.0.5_8-jdk-noble
ARG JRE_IMAGE=eclipse-temurin:25.0.5_8-jre-noble

FROM ${JDK_IMAGE} AS build
WORKDIR /project
COPY settings.gradle.kts build.gradle.kts ./
COPY gradle ./gradle
COPY gradlew ./
COPY bloodhound-common ./bloodhound-common
COPY central-server ./central-server
COPY worker/build.gradle.kts ./worker/build.gradle.kts
COPY webui/backend/build.gradle.kts ./webui/backend/build.gradle.kts
RUN ./gradlew :central-server:bootJar --no-daemon -x test

FROM ${JRE_IMAGE}
# curl: the compose healthcheck; the JRE image doesn't ship it.
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build --chown=1000:1000 /project/central-server/build/libs/central-server.jar app.jar
# A container-hardening review found every service in this repo ran as root by default (no USER
# directive anywhere) - the standard CIS Docker Benchmark/OWASP Docker Top 10 gap. Numeric
# UID:GID rather than a named user - no dependency on useradd/shadow-utils being present in this
# base image, and Docker honors a bare UID:GID for USER without any /etc/passwd entry existing.
USER 1000:1000
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
