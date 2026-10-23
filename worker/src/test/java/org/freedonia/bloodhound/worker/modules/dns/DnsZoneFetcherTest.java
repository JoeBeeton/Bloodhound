package org.freedonia.bloodhound.worker.modules.dns;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;

/**
 * A security review found DnsZoneFetcher#attemptAxfr had no cap on AXFR record count/bytes at
 * all - dnsjava's default (handler-less) run() buffers every transferred record into one
 * in-memory list with no limit, bounded only by a 6-second idle timeout a fast-streaming
 * nameserver could avoid ever hitting. These tests cover the pure record-capping logic
 * (DnsZoneFetcher.CappedAxfrHandler) directly, without a real network transfer - attemptAxfr
 * itself makes a live DNS connection, so (like every other network-calling method in this
 * package) it isn't unit tested; this is the pure logic extracted from it that is.
 */
class DnsZoneFetcherTest {

    private static Record record(String hostname) throws TextParseException, UnknownHostException {
        return new ARecord(Name.fromString(hostname + "."), DClass.IN, 300, InetAddress.getByName("192.0.2.1"));
    }

    /** ~2.6KB on the wire (ten 255-byte TXT strings) - a few thousand of these cross MAX_AXFR_BYTES long before MAX_AXFR_RECORDS would. */
    private static Record bigRecord(String hostname) throws TextParseException {
        return new TXTRecord(
                Name.fromString(hostname + "."), DClass.IN, 300, java.util.Collections.nCopies(10, "x".repeat(255)));
    }

    @Test
    void underTheCap_collectsEveryRecord() throws Exception {
        DnsZoneFetcher.CappedAxfrHandler handler = new DnsZoneFetcher.CappedAxfrHandler();

        handler.handleRecord(record("a.example.com"));
        handler.handleRecord(record("b.example.com"));

        assertThat(handler.records).hasSize(2);
    }

    @Test
    void exceedingTheCap_throwsAxfrRecordCapExceeded_afterCollectingExactlyTheCappedAmount() throws Exception {
        DnsZoneFetcher.CappedAxfrHandler handler = new DnsZoneFetcher.CappedAxfrHandler();
        for (int i = 0; i < DnsZoneFetcher.MAX_AXFR_RECORDS; i++) {
            handler.handleRecord(record(i + ".example.com"));
        }

        assertThatThrownBy(() -> handler.handleRecord(record("one-too-many.example.com")))
                .isInstanceOf(DnsZoneFetcher.AxfrRecordCapExceeded.class);
        // The cap-exceeding record itself is never added - the transfer stops exactly at the cap,
        // not one past it.
        assertThat(handler.records).hasSize(DnsZoneFetcher.MAX_AXFR_RECORDS);
    }

    /**
     * A rules-parity review found the record-count cap alone assumes every record is small -
     * a handful of oversized records (TXT/RRSIG, say) could exhaust significant memory well
     * before hitting 50,000 of them. This proves the byte cap trips first in exactly that shape.
     */
    @Test
    void exceedingTheByteCap_throwsBeforeEverReachingTheRecordCountCap() throws Exception {
        DnsZoneFetcher.CappedAxfrHandler handler = new DnsZoneFetcher.CappedAxfrHandler();

        assertThatThrownBy(() -> {
            for (int i = 0; i < DnsZoneFetcher.MAX_AXFR_RECORDS; i++) {
                handler.handleRecord(bigRecord(i + ".example.com"));
            }
        }).isInstanceOf(DnsZoneFetcher.AxfrRecordCapExceeded.class);

        assertThat(handler.records.size()).isLessThan(DnsZoneFetcher.MAX_AXFR_RECORDS);
    }

    @Test
    void axfrRecordCapExceeded_isUnchecked_soItCanEscapeTheInterfacesCheckedThrowsClause() {
        // handleRecord's own declared signature only permits a checked ZoneTransferException -
        // the whole point of this exception being a RuntimeException is that it can still
        // propagate through that signature undeclared, straight past dnsjava's internal transfer
        // loop to attemptAxfr's own catch block.
        assertThat(RuntimeException.class).isAssignableFrom(DnsZoneFetcher.AxfrRecordCapExceeded.class);
    }
}
