// Plain Java library — shared DTOs and the ScanModule SPI.
// No Spring Boot plugin here: this module must stay a lightweight dependency
// for both central-server and worker without pulling in a Boot runtime.

dependencies {
    // Versions kept in step with what central-server's Spring Boot BOM resolves, so test
    // behavior doesn't drift between modules. Gradle 9 no longer supplies the launcher itself.
    testImplementation("org.junit.jupiter:junit-jupiter:6.0.3")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:6.0.3")
    // Needed here (unlike SafeAddressValidatorTest's plain-JUnit style) to mock
    // java.net.http.HttpClient/HttpResponse for SafeHttpGetTest without real network calls.
    testImplementation("org.mockito:mockito-core:5.23.0")
}
