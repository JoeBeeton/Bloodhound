// Plain Java library — shared DTOs and the ScanModule SPI.
// No Spring Boot plugin here: this module must stay a lightweight dependency
// for both central-server and worker without pulling in a Boot runtime.

dependencies {
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
}
