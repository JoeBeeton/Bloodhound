# Build context is the repo root.
# Same pinned Temurin release as central-server's Dockerfile - see there.
ARG JDK_IMAGE=eclipse-temurin:25.0.5_8-jdk-noble
ARG JRE_IMAGE=eclipse-temurin:25.0.5_8-jre-noble

FROM node:22-slim AS frontend-build
WORKDIR /frontend
COPY webui/frontend/package.json webui/frontend/package-lock.json* ./
RUN npm install
COPY webui/frontend ./
RUN npm run build

# settings.gradle.kts includes all four modules, so Gradle needs every project
# directory present to evaluate the build even though we only assemble
# webui-backend's jar here.
FROM ${JDK_IMAGE} AS build
WORKDIR /project
COPY settings.gradle.kts build.gradle.kts ./
COPY gradle ./gradle
COPY gradlew ./
COPY webui/backend ./webui/backend
COPY bloodhound-common/build.gradle.kts ./bloodhound-common/build.gradle.kts
COPY central-server/build.gradle.kts ./central-server/build.gradle.kts
COPY worker/build.gradle.kts ./worker/build.gradle.kts
COPY --from=frontend-build /frontend/dist ./webui/backend/src/main/resources/static
RUN ./gradlew :webui-backend:bootJar --no-daemon -x test

FROM ${JRE_IMAGE}
# curl: the compose healthcheck; the JRE image doesn't ship it.
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build --chown=1000:1000 /project/webui/backend/build/libs/webui.jar app.jar
# Same container-hardening fix as central-server's own Dockerfile - see its comment for why a
# bare numeric UID:GID rather than a named user.
USER 1000:1000
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
