# Build context is the repo root (multi-module Gradle build). settings.gradle.kts
# includes all four modules, so Gradle needs every project directory present
# to evaluate the build even though we only assemble central-server's jar here.
FROM gradle:8.12-jdk21 AS build
WORKDIR /project
COPY settings.gradle.kts build.gradle.kts ./
COPY gradle ./gradle
COPY gradlew ./
COPY bloodhound-common ./bloodhound-common
COPY central-server ./central-server
COPY worker/build.gradle.kts ./worker/build.gradle.kts
COPY webui/backend/build.gradle.kts ./webui/backend/build.gradle.kts
RUN ./gradlew :central-server:bootJar --no-daemon -x test

FROM ghcr.io/graalvm/jdk-community:21
WORKDIR /app
COPY --from=build /project/central-server/build/libs/central-server.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
