package org.freedonia.bloodhound.worker.modules.exposure;

import java.util.Map;

/**
 * @param baseline response to a definitely-nonexistent random path, used by decision logic
 *     to suppress "soft-404" sites that return 200 for every path
 * @param responses ruleId -> best (first 200, else last attempted) response
 * @param redisResponse raw bytes-as-string read after sending INFO\r\n to :6379, or null if unreachable
 * @param sourceMapResponses same-host {@code <script src>} URL (as found on the homepage) -> the
 *     response fetched for that same URL with ".map" appended - see EXPOSURE_JS_SOURCE_MAP
 * @param jdwpResponses port (5005 or 8000, JDWP's two conventional debug ports - unlike Redis
 *     there's no single universal default) -> raw bytes-as-string read after sending the
 *     "JDWP-Handshake" ASCII string, or absent if unreachable on that port
 * @param rabbitMqResponse response to GET /api/whoami on :15672 with the guest:guest default
 *     credential pair - see EXPOSURE_RABBITMQ_DEFAULT_CREDS
 * @param vncResponse raw bytes-as-string: the server's 12-byte RFB version banner followed by its
 *     security-type-list reply on :5900, or null if unreachable - see EXPOSURE_VNC_NO_AUTH
 * @param snmpResponse raw bytes-as-string read after sending an SNMPv1 GetRequest for sysDescr.0
 *     with community "public" to UDP :161, or null if no response - see
 *     EXPOSURE_SNMP_DEFAULT_COMMUNITY
 */
public record ExposedPathFetchResult(
        ProbeResponse baseline,
        Map<String, ProbeResponse> responses,
        String redisResponse,
        Map<String, ProbeResponse> sourceMapResponses,
        Map<Integer, String> jdwpResponses,
        ProbeResponse rabbitMqResponse,
        String vncResponse,
        String snmpResponse) {

    /** Test convenience - production code always populates every field below baseline/responses/redisResponse. */
    ExposedPathFetchResult(ProbeResponse baseline, Map<String, ProbeResponse> responses, String redisResponse) {
        this(baseline, responses, redisResponse, Map.of(), Map.of(), ProbeResponse.unreachable(), null, null);
    }

    /** Test convenience for cases exercising sourceMapResponses specifically. */
    ExposedPathFetchResult(
            ProbeResponse baseline,
            Map<String, ProbeResponse> responses,
            String redisResponse,
            Map<String, ProbeResponse> sourceMapResponses) {
        this(baseline, responses, redisResponse, sourceMapResponses, Map.of(), ProbeResponse.unreachable(), null, null);
    }

    /** Test convenience for cases exercising jdwpResponses specifically. */
    ExposedPathFetchResult(
            ProbeResponse baseline,
            Map<String, ProbeResponse> responses,
            String redisResponse,
            Map<String, ProbeResponse> sourceMapResponses,
            Map<Integer, String> jdwpResponses) {
        this(baseline, responses, redisResponse, sourceMapResponses, jdwpResponses, ProbeResponse.unreachable(), null, null);
    }

    /** Test convenience for cases exercising rabbitMqResponse specifically. */
    ExposedPathFetchResult(
            ProbeResponse baseline,
            Map<String, ProbeResponse> responses,
            String redisResponse,
            Map<String, ProbeResponse> sourceMapResponses,
            Map<Integer, String> jdwpResponses,
            ProbeResponse rabbitMqResponse) {
        this(baseline, responses, redisResponse, sourceMapResponses, jdwpResponses, rabbitMqResponse, null, null);
    }
}
