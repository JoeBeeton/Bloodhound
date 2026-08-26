package org.freedonia.bloodhound.worker.modules.exposure;

import java.util.Map;

/**
 * @param baseline response to a definitely-nonexistent random path, used by decision logic
 *     to suppress "soft-404" sites that return 200 for every path
 * @param responses ruleId -> best (first 200, else last attempted) response
 * @param redisResponse raw bytes-as-string read after sending INFO\r\n to :6379, or null if unreachable
 */
public record ExposedPathFetchResult(
        ProbeResponse baseline, Map<String, ProbeResponse> responses, String redisResponse) {}
