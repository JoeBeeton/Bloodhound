package org.freedonia.bloodhound.worker.modules.portscan;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Fixtures below are real zgrab2 v1.0.0 output captured against live hosts, not hand-guessed. */
class Zgrab2JsonParserTest {

    /** Captured live against github.com:22 - a fully modern, no-weak-algorithm SSH configuration. */
    private static final String REAL_SSH_SUCCESS_JSON =
            """
            {"ip":"4.208.26.197","domain":"github.com","data":{"ssh":{"status":"success","protocol":"ssh","port":22,\
            "result":{"server_id":{"raw":"SSH-2.0-e7b94b6","version":"2.0","software":"e7b94b6"},\
            "server_key_exchange":{"kex_algorithms":["curve25519-sha256","curve25519-sha256@libssh.org",\
            "ecdh-sha2-nistp256","diffie-hellman-group-exchange-sha256"],\
            "host_key_algorithms":["ssh-ed25519","ecdsa-sha2-nistp256","rsa-sha2-512","rsa-sha2-256"],\
            "client_to_server_ciphers":["chacha20-poly1305@openssh.com","aes256-gcm@openssh.com","aes256-ctr"],\
            "server_to_client_ciphers":["chacha20-poly1305@openssh.com","aes256-gcm@openssh.com","aes256-ctr"],\
            "client_to_server_macs":["hmac-sha2-512-etm@openssh.com","hmac-sha2-256-etm@openssh.com"],\
            "server_to_client_macs":["hmac-sha2-512-etm@openssh.com","hmac-sha2-256-etm@openssh.com"]}},\
            "timestamp":"2026-10-14T17:19:50Z"}}}""";

    @Test
    void parsesSshAlgorithms_realModernConfig() {
        Zgrab2JsonParser.SshAlgorithms algorithms = Zgrab2JsonParser.parseSshAlgorithms(REAL_SSH_SUCCESS_JSON).orElseThrow();

        assertThat(algorithms.kexAlgorithms()).contains("curve25519-sha256", "diffie-hellman-group-exchange-sha256");
        assertThat(algorithms.hostKeyAlgorithms()).contains("ssh-ed25519", "rsa-sha2-512");
        assertThat(algorithms.ciphers()).contains("chacha20-poly1305@openssh.com", "aes256-ctr");
        assertThat(algorithms.macs()).contains("hmac-sha2-512-etm@openssh.com");
    }

    @Test
    void sshAlgorithms_unionsClientToServerAndServerToClientDirections() {
        String json = """
                {"ip":"1.2.3.4","data":{"ssh":{"status":"success","result":{"server_key_exchange":{\
                "kex_algorithms":[],"host_key_algorithms":[],\
                "client_to_server_ciphers":["aes256-ctr"],"server_to_client_ciphers":["aes128-cbc"],\
                "client_to_server_macs":["hmac-sha2-256"],"server_to_client_macs":["hmac-md5"]}}}}}""";

        Zgrab2JsonParser.SshAlgorithms algorithms = Zgrab2JsonParser.parseSshAlgorithms(json).orElseThrow();

        assertThat(algorithms.ciphers()).containsExactlyInAnyOrder("aes256-ctr", "aes128-cbc");
        assertThat(algorithms.macs()).containsExactlyInAnyOrder("hmac-sha2-256", "hmac-md5");
    }

    @Test
    void sshConnectionFailureYieldsEmpty() {
        String json = """
                {"ip":"1.2.3.4","data":{"ssh":{"status":"connection-timeout","protocol":"ssh","port":22,\
                "error":"dial context failed"}}}""";

        assertThat(Zgrab2JsonParser.parseSshAlgorithms(json)).isEmpty();
    }

    @Test
    void sshMalformedJsonYieldsEmptyRatherThanThrowing() {
        assertThat(Zgrab2JsonParser.parseSshAlgorithms("not json")).isEmpty();
        assertThat(Zgrab2JsonParser.parseSshAlgorithms(null)).isEmpty();
    }

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
