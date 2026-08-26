package org.freedonia.bloodhound.worker.modules.portscan;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Fixtures below are real zgrab2 v1.0.0 output captured against live hosts, not hand-guessed. */
class Zgrab2JsonParserTest {

    @Test
    void parsesSuccessfulSshBanner() {
        String json = """
                {"ip":"45.33.32.156","data":{"banner":{"status":"success","protocol":"banner","port":22,\
                "result":{"banner":"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13\\r\\nProtocol mismatch.\\n","length":63},\
                "timestamp":"2026-08-25T11:17:49+01:00"}}}""";

        assertThat(Zgrab2JsonParser.parseBannerText(json).orElseThrow())
                .startsWith("SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13");
    }

    @Test
    void bannerConnectionFailureYieldsEmpty() {
        String json = """
                {"ip":"45.33.32.156","data":{"banner":{"status":"connection-timeout","protocol":"banner","port":12345,\
                "timestamp":"2026-08-25T11:18:10+01:00","error":"failed to connect to 45.33.32.156: dial context failed"}}}""";

        assertThat(Zgrab2JsonParser.parseBannerText(json)).isEmpty();
    }

    @Test
    void parsesHttpServerHeader() {
        String json = """
                {"ip":"45.33.32.156","domain":"example.com","data":{"http":{"status":"success","protocol":"http",\
                "port":80,"result":{"response":{"status_line":"200 OK","status_code":200,\
                "headers":{"server":["Apache/2.4.7 (Ubuntu)"],"content_type":["text/html"]}}},\
                "timestamp":"2026-08-25T11:18:00+01:00"}}}""";

        assertThat(Zgrab2JsonParser.parseHttpServerHeader(json)).contains("Apache/2.4.7 (Ubuntu)");
    }

    @Test
    void httpWithNoServerHeaderYieldsEmpty() {
        String json = """
                {"ip":"1.2.3.4","data":{"http":{"status":"success","protocol":"http","port":80,\
                "result":{"response":{"status_line":"200 OK","status_code":200,"headers":{}}}}}}""";

        assertThat(Zgrab2JsonParser.parseHttpServerHeader(json)).isEmpty();
    }

    @Test
    void malformedJsonYieldsEmptyRatherThanThrowing() {
        assertThat(Zgrab2JsonParser.parseBannerText("not json")).isEmpty();
        assertThat(Zgrab2JsonParser.parseHttpServerHeader("")).isEmpty();
        assertThat(Zgrab2JsonParser.parseBannerText(null)).isEmpty();
    }
}
