plugins {
    id("org.springframework.boot")
    id("io.spring.dependency-management")
}

dependencyManagement {
    imports {
        mavenBom("org.springframework.boot:spring-boot-dependencies:3.4.1")
    }
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
}

tasks.named<org.springframework.boot.gradle.tasks.bundling.BootJar>("bootJar") {
    archiveFileName.set("worker.jar")
}
