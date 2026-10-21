plugins {
    id("org.springframework.boot")
    id("io.spring.dependency-management")
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.boot:spring-boot-dependencies:3.5.16")
    }
}

// Separate from the unit-test source set so `./gradlew test` never binds ports or
// needs the network namespace. Run scripts/run-rule-integration-tests.sh.
val ruleIntegrationTestSourceSet = sourceSets.create("ruleIntegrationTest") {
    // Gradle already maps this name to src/ruleIntegrationTest/{java,resources}.
    // Adding those directories again makes processResources see each file twice.
    compileClasspath += sourceSets.main.get().output
    runtimeClasspath += sourceSets.main.get().output
}

configurations.named("ruleIntegrationTestImplementation") {
    extendsFrom(configurations.named("implementation").get(), configurations.named("testImplementation").get())
}
configurations.named("ruleIntegrationTestRuntimeOnly") {
    extendsFrom(configurations.named("runtimeOnly").get(), configurations.named("testRuntimeOnly").get())
}

dependencies {
    implementation(project(":bloodhound-common"))

    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    // Pure-Java DNS record queries (TXT/CAA/DNSKEY) for DnsPostureModule -
    // no native deps, avoids the fiddlier raw JNDI DNS context API.
    implementation("dnsjava:dnsjava:3.6.1")
    // Document-metadata extraction (DocumentMetadataModule) - both Apache
    // Software Foundation projects, Apache-2.0, license-checked against
    // each project's actual LICENSE file before adding (same discipline as
    // every other third-party tool in this codebase). pdfbox for PDF;
    // poi-ooxml for modern Office XML (.docx/.xlsx/.pptx) core/extended
    // properties. Legacy binary Office (.doc/.xls/.ppt) metadata is read via
    // POI's HPSF property-set API (org.apache.poi.hpsf, part of the base
    // "poi" artifact pulled in transitively by poi-ooxml) directly against
    // the OLE2 SummaryInformation/DocumentSummaryInformation streams - that
    // API is format-agnostic (a standard OLE2 convention, not specific to
    // Word/Excel/PowerPoint), so poi-scratchpad's format-specific text
    // extractors (HWPF/HSLF/etc.) are never needed just to read metadata.
    implementation("org.apache.pdfbox:pdfbox:3.0.7")
    implementation("org.apache.poi:poi-ooxml:5.5.1")

    testImplementation("org.springframework.boot:spring-boot-starter-test")

    // Test-only: CompoundRiskEngine lives in central-server and the worker must not
    // depend on it at runtime. The engine and Finding are plain Java, so the suite
    // uses the jar only and does not pull central-server's Boot 4 / Spring AI graph
    // onto the worker's Boot 3 classpath.
    add("ruleIntegrationTestImplementation", project(":central-server")) {
        isTransitive = false
    }
}

tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
    archiveFileName.set("worker.jar")
}

val ruleFixtureDir = layout.buildDirectory.dir("rule-fixture")
val ruleSecurityFile = layout.projectDirectory.file("src/ruleIntegrationTest/resources/rule-integration.security")
val ruleExports = listOf(
    "--add-exports=java.base/sun.security.x509=ALL-UNNAMED",
    "--add-exports=java.base/sun.security.util=ALL-UNNAMED",
)

tasks.named<JavaCompile>("compileRuleIntegrationTestJava") {
    options.compilerArgs.addAll(ruleExports)
}

tasks.register<JavaExec>("generateRuleFixtureMaterial") {
    group = "verification"
    description = "Regenerates rule-integration TLS material with dates relative to now."
    classpath = ruleIntegrationTestSourceSet.runtimeClasspath
    mainClass.set("org.freedonia.bloodhound.worker.ruleit.CertMaterial")
    argumentProviders.add(object : org.gradle.process.CommandLineArgumentProvider {
        override fun asArguments(): Iterable<String> = listOf(ruleFixtureDir.get().asFile.absolutePath)
    })
    outputs.dir(ruleFixtureDir)
    outputs.upToDateWhen { false }
    javaLauncher.set(javaToolchains.launcherFor {
        languageVersion.set(JavaLanguageVersion.of(21))
    })
    jvmArgs(ruleExports)
}

tasks.register<Test>("ruleIntegrationTest") {
    group = "verification"
    description = "Real scan modules against a local fixture. Run scripts/run-rule-integration-tests.sh."
    testClassesDirs = ruleIntegrationTestSourceSet.output.classesDirs
    classpath = ruleIntegrationTestSourceSet.runtimeClasspath
    useJUnitPlatform()
    shouldRunAfter(tasks.named("test"))
    dependsOn("generateRuleFixtureMaterial")
    maxParallelForks = 1
    // Read defensively, not just lazily within this already-lazy register{} block: a
    // container image's Dockerfile builds a single module (e.g. central-server/Dockerfile
    // copies only worker/build.gradle.kts, never worker/src/) but Gradle still configures
    // every subproject's build script to resolve the full task graph, so this file may
    // genuinely not exist in that context even though this specific task is never run
    // there. A missing allowlist here just means "no hosts" - correct, since the task
    // that would need it never executes in that build.
    val allowlist = layout.projectDirectory.file("src/ruleIntegrationTest/resources/ssrf-allowlist.txt").asFile
    val hosts = if (allowlist.exists()) {
        allowlist.readLines().map { it.substringBefore("#").trim() }.filter { it.isNotEmpty() }
    } else {
        emptyList()
    }
    environment("BLOODHOUND_SSRF_ALLOWLIST", hosts.joinToString(","))
    systemProperty("javax.net.ssl.trustStore", ruleFixtureDir.get().file("truststore.p12").asFile.absolutePath)
    systemProperty("javax.net.ssl.trustStorePassword", "changeit")
    systemProperty("javax.net.ssl.trustStoreType", "PKCS12")
    systemProperty("bloodhound.rule.fixture.dir", ruleFixtureDir.get().asFile.absolutePath)
    // Append (path does not start with '='). Overrides jdk.tls.disabledAlgorithms before ProtocolVersion initializes.
    jvmArgs(ruleExports + listOf("-Djava.security.properties=${ruleSecurityFile.asFile.absolutePath}"))
    javaLauncher.set(javaToolchains.launcherFor {
        languageVersion.set(JavaLanguageVersion.of(21))
    })
    // Gradle 9's failOnNoDiscoveredTests is absent on 8.14. A match-all filter
    // with failOnNoMatchingTests fails the task when JUnit discovers nothing.
    filter {
        isFailOnNoMatchingTests = true
        includeTestsMatching("*")
    }
    testLogging {
        events(
            org.gradle.api.tasks.testing.logging.TestLogEvent.PASSED,
            org.gradle.api.tasks.testing.logging.TestLogEvent.SKIPPED,
            org.gradle.api.tasks.testing.logging.TestLogEvent.FAILED,
        )
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
