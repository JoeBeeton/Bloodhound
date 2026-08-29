plugins {
    id("org.springframework.boot")
    id("io.spring.dependency-management")
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.boot:spring-boot-dependencies:4.1.1")
    }
}

dependencies {
    implementation(project(":bloodhound-common"))

    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.springframework.security:spring-security-saml2-service-provider")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-validation")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    // Boot 4's own Flyway starter only pulls in flyway-core - the PostgreSQL-specific database
    // support module is still a separate dependency (confirmed live: without it, Flyway throws
    // "Unsupported Database: PostgreSQL 16.15" at startup), same as it was on Boot 3.
    implementation("org.springframework.boot:spring-boot-starter-flyway")
    implementation("org.flywaydb:flyway-database-postgresql")
    runtimeOnly("org.postgresql:postgresql")

    implementation("io.jsonwebtoken:jjwt-api:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.6")
    runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.6")

    // OpenAPI/Swagger UI for the external read-only API (Apache-2.0). Serves the
    // generated spec + interactive docs from the same running app, no separate
    // toolchain - see config.OpenApiConfig for the apiKey security scheme.
    // 3.x line specifically: springdoc-openapi's major version tracks Spring Boot's
    // major version in lockstep, so this must move in step with the Boot 4 bump above.
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:3.1.0")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
    archiveFileName.set("central-server.jar")
}
