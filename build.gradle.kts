plugins {
    java
    id("org.springframework.boot") version "3.4.1" apply false
    id("io.spring.dependency-management") version "1.1.7" apply false
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
