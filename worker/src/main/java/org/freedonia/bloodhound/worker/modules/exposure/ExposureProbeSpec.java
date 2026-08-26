package org.freedonia.bloodhound.worker.modules.exposure;

import java.util.List;

/**
 * One entry in the exposure-probe catalog. {@code paths} are tried in order,
 * first 200 response wins. {@code altPort} null means the default 443
 * (HTTPS, falling back to 80/HTTP on connection failure); non-null means a
 * plain-HTTP probe on that specific non-standard port (Docker/Elasticsearch/
 * Consul). {@code skipBody} is only true for the heapdump probe, which is
 * checked by status+content-type alone so a multi-gigabyte dump is never
 * actually downloaded.
 */
public record ExposureProbeSpec(
        String ruleId, List<String> paths, String method, String postBody, Integer altPort, boolean skipBody) {

    static ExposureProbeSpec get(String ruleId, List<String> paths) {
        return new ExposureProbeSpec(ruleId, paths, "GET", null, null, false);
    }

    static ExposureProbeSpec getNoBody(String ruleId, List<String> paths) {
        return new ExposureProbeSpec(ruleId, paths, "GET", null, null, true);
    }

    static ExposureProbeSpec post(String ruleId, String path, String body) {
        return new ExposureProbeSpec(ruleId, List.of(path), "POST", body, null, false);
    }

    static ExposureProbeSpec altPort(String ruleId, String path, int port) {
        return new ExposureProbeSpec(ruleId, List.of(path), "GET", null, port, false);
    }
}
