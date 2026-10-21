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
 */
public record ExposedPathFetchResult(
        ProbeResponse baseline,
        Map<String, ProbeResponse> responses,
        String redisResponse,
        Map<String, ProbeResponse> sourceMapResponses,
        Map<Integer, String> jdwpResponses,
        ProbeResponse rabbitMqResponse) {

    /** Test convenience - production code always populates sourceMapResponses/jdwpResponses/rabbitMqResponse. */
    ExposedPathFetchResult(ProbeResponse baseline, Map<String, ProbeResponse> responses, String redisResponse) {
        this(baseline, responses, redisResponse, Map.of(), Map.of(), ProbeResponse.unreachable());
    }

    /** Test convenience for cases exercising sourceMapResponses specifically. */
    ExposedPathFetchResult(
            ProbeResponse baseline,
            Map<String, ProbeResponse> responses,
            String redisResponse,
            Map<String, ProbeResponse> sourceMapResponses) {
        this(baseline, responses, redisResponse, sourceMapResponses, Map.of(), ProbeResponse.unreachable());
    }

    /** Test convenience for cases exercising jdwpResponses specifically. */
    ExposedPathFetchResult(
            ProbeResponse baseline,
            Map<String, ProbeResponse> responses,
            String redisResponse,
            Map<String, ProbeResponse> sourceMapResponses,
            Map<Integer, String> jdwpResponses) {
        this(baseline, responses, redisResponse, sourceMapResponses, jdwpResponses, ProbeResponse.unreachable());
    }
}
