package org.freedonia.bloodhound.server.botnet;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDate;
import java.util.List;
import org.junit.jupiter.api.Test;

class FeodoTrackerClientTest {

    private final FeodoTrackerClient client = new FeodoTrackerClient();

    /** The real, live-captured feed shape (abbreviated to the two statuses that matter). */
    private static final String REAL_FEED_SHAPE =
            """
            [
                {
                    "ip_address": "162.243.103.246",
                    "port": 8080,
                    "status": "offline",
                    "hostname": null,
                    "as_number": 14061,
                    "as_name": "DIGITALOCEAN-ASN",
                    "country": "US",
                    "first_seen": "2022-06-04 21:24:53",
                    "last_online": "2026-03-07",
                    "malware": "Emotet"
                },
                {
                    "ip_address": "50.16.16.211",
                    "port": 443,
                    "status": "online",
                    "hostname": "ec2-50-16-16-211.compute-1.amazonaws.com",
                    "as_number": 14618,
                    "as_name": "AMAZON-AES",
                    "country": "US",
                    "first_seen": "2025-12-30 13:56:31",
                    "last_online": "2026-03-12",
                    "malware": "QakBot"
                }
            ]
            """;

    @Test
    void parse_onlyKeepsOnlineEntries() {
        List<BotnetIpEntry> entries = client.parse(REAL_FEED_SHAPE);

        assertThat(entries).hasSize(1);
        assertThat(entries.get(0).ipAddress()).isEqualTo("50.16.16.211");
        assertThat(entries.get(0).malware()).isEqualTo("QakBot");
    }

    @Test
    void parse_extractsDatePartOfSpaceSeparatedFirstSeenTimestamp() {
        List<BotnetIpEntry> entries = client.parse(REAL_FEED_SHAPE);

        assertThat(entries.get(0).firstSeen()).isEqualTo(LocalDate.of(2025, 12, 30));
    }

    @Test
    void parse_allOffline_yieldsEmptyList() {
        String json = """
                [{"ip_address": "1.2.3.4", "status": "offline", "malware": "Emotet", "first_seen": "2022-01-01 00:00:00"}]
                """;
        assertThat(client.parse(json)).isEmpty();
    }

    @Test
    void parse_emptyArray_yieldsEmptyList() {
        assertThat(client.parse("[]")).isEmpty();
    }

    @Test
    void parse_nullInput_yieldsEmptyList() {
        assertThat(client.parse(null)).isEmpty();
    }

    @Test
    void parse_malformedJson_yieldsEmptyListRatherThanThrowing() {
        assertThat(client.parse("not json")).isEmpty();
    }

    @Test
    void parse_onlineEntryMissingIpAddress_skippedRatherThanNullPointer() {
        String json = """
                [{"status": "online", "malware": "QakBot", "first_seen": "2025-01-01 00:00:00"}]
                """;
        assertThat(client.parse(json)).isEmpty();
    }

    @Test
    void parse_unparseableFirstSeenDate_leavesItNullRatherThanThrowing() {
        String json = """
                [{"ip_address": "1.2.3.4", "status": "online", "malware": "QakBot", "first_seen": "garbage"}]
                """;
        List<BotnetIpEntry> entries = client.parse(json);
        assertThat(entries).hasSize(1);
        assertThat(entries.get(0).firstSeen()).isNull();
    }
}
