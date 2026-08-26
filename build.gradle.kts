plugins {
    java
    id("org.springframework.boot") version "3.4.1" apply false
    id("io.spring.dependency-management") version "1.1.7" apply false
    // SBOM generation (CycloneDX Software Foundation, Apache-2.0 - build-time
    // tooling only, never shipped in a runtime artifact, so the license bar
    // here is lower than for runtime dependencies, but it's Apache-2.0
    // anyway). Applied once at root: this build's default "aggregate" mode
    // produces one CycloneDX SBOM covering every subproject's dependencies
    // (bloodhound-common, central-server, worker, webui/backend) rather than
    // one per deployable - simplest useful default; split into per-module
    // SBOMs later if per-container-image provenance is ever needed.
    id("org.cyclonedx.bom") version "3.4.1"
}

allprojects {
    group = "org.freedonia.bloodhound"
    version = "0.1.0-SNAPSHOT"

    repositories {
        mavenCentral()
        // OpenSAML (a transitive dependency of spring-security-saml2-service-provider)
        // isn't published to Maven Central - Shibboleth hosts it themselves.
        maven { url = uri("https://build.shibboleth.net/nexus/content/repositories/releases/") }
    }
}

subprojects {
    apply(plugin = "java")

    java {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(21))
        }
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }
}
