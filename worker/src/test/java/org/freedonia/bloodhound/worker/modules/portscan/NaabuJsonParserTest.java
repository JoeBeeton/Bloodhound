package org.freedonia.bloodhound.worker.modules.portscan;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Fixtures below are real naabu v2.6.1 -json -silent output, not hand-guessed. */
class NaabuJsonParserTest {

    @Test
    void parsesOpenPortsFromRealOutput() {
        String output = """
                {"ip":"45.33.32.156","timestamp":"2026-08-25T10:16:53.118497825Z","port":443,"protocol":"tcp","tls":false}
                {"ip":"45.33.32.156","timestamp":"2026-08-25T10:16:53.118716695Z","port":9929,"protocol":"tcp","tls":false}
                {"ip":"45.33.32.156","timestamp":"2026-08-25T10:16:53.118785795Z","port":22,"protocol":"tcp","tls":false}
                {"ip":"45.33.32.156","timestamp":"2026-08-25T10:16:53.118809139Z","port":80,"protocol":"tcp","tls":false}
                """;

        assertThat(NaabuJsonParser.parseOpenPorts(output)).containsExactly(22, 80, 443, 9929);
    }

    @Test
    void deduplicatesRetriedPorts() {
        String output = """
                {"ip":"1.2.3.4","port":22,"protocol":"tcp","tls":false}
                {"ip":"1.2.3.4","port":22,"protocol":"tcp","tls":false}
                {"ip":"1.2.3.4","port":22,"protocol":"tcp","tls":false}
                """;

        assertThat(NaabuJsonParser.parseOpenPorts(output)).containsExactly(22);
    }

    @Test
    void ignoresBlankAndMalformedLines() {
        String output = """
                {"ip":"1.2.3.4","port":22,"protocol":"tcp","tls":false}

                not json
                {"ip":"1.2.3.4","port":80,"protocol":"tcp","tls":false}
                """;

        assertThat(NaabuJsonParser.parseOpenPorts(output)).containsExactly(22, 80);
    }

    @Test
    void emptyOrBlankInputYieldsNoPorts() {
        assertThat(NaabuJsonParser.parseOpenPorts("")).isEmpty();
        assertThat(NaabuJsonParser.parseOpenPorts(null)).isEmpty();
        assertThat(NaabuJsonParser.parseOpenPorts("   ")).isEmpty();
    }

    @Test
    void resultIsSorted() {
        String output = """
                {"ip":"1.2.3.4","port":9092,"protocol":"tcp","tls":false}
                {"ip":"1.2.3.4","port":22,"protocol":"tcp","tls":false}
                {"ip":"1.2.3.4","port":443,"protocol":"tcp","tls":false}
                """;

        assertThat(NaabuJsonParser.parseOpenPorts(output)).containsExactly(22, 443, 9092);
    }
}
