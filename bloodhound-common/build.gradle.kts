// Plain Java library — shared DTOs and the ScanModule SPI.
// No Spring Boot plugin here: this module must stay a lightweight dependency
// for both central-server and worker without pulling in a Boot runtime.

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    // MIT-licensed, matches the version Spring Boot 3.4.1's dependency-management BOM
    // resolves for central-server/worker's tests (via spring-boot-starter-test) - kept in
    // step so mocking behavior doesn't drift between modules. Needed here (unlike
    // SafeAddressValidatorTest's plain-JUnit style) to mock java.net.http.HttpClient/
    // HttpResponse for SafeHttpGetTest without making real network calls.
    testImplementation("org.mockito:mockito-core:5.14.2")
}
