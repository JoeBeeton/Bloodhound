package org.freedonia.bloodhound.worker.modules.exposure;

import java.util.List;

/**
 * One entry in the exposure-probe catalog. {@code paths} are tried in order,
 * first 200 response wins. {@code altPort} null means the default 443
 * (HTTPS, falling back to 80/HTTP on connection failure); non-null means an
 * alt-port probe on that specific non-standard port (Docker/Elasticsearch/
 * Consul/Grafana/Mongo Express/Traefik all serve plain HTTP on their alt
 * port, so {@code altPortHttps} is false for those). {@code altPortHttps}
 * true means the alt port instead needs HTTPS with a permissive (self-signed-
 * tolerant) trust manager - the Kubernetes API server is the one alt-port
 * service in this catalog that never serves plain HTTP at all; its cluster
 * CA is essentially never in any public trust store. {@code skipBody} is
 * only true for the heapdump probe, which is checked by status+content-type
 * alone so a multi-gigabyte dump is never actually downloaded.
 */
public record ExposureProbeSpec(
        String ruleId,
        List<String> paths,
        String method,
        String postBody,
        Integer altPort,
        boolean altPortHttps,
        boolean skipBody) {

    static ExposureProbeSpec get(String ruleId, List<String> paths) {
        return new ExposureProbeSpec(ruleId, paths, "GET", null, null, false, false);
    }

    static ExposureProbeSpec getNoBody(String ruleId, List<String> paths) {
        return new ExposureProbeSpec(ruleId, paths, "GET", null, null, false, true);
    }

    static ExposureProbeSpec post(String ruleId, String path, String body) {
        return new ExposureProbeSpec(ruleId, List.of(path), "POST", body, null, false, false);
    }

    static ExposureProbeSpec altPort(String ruleId, String path, int port) {
        return new ExposureProbeSpec(ruleId, List.of(path), "GET", null, port, false, false);
    }

    static ExposureProbeSpec altPortHttps(String ruleId, String path, int port) {
        return new ExposureProbeSpec(ruleId, List.of(path), "GET", null, port, true, false);
    }

    /** Like {@link #post} but on a non-default port - etcd's v3 gRPC-gateway KV API requires POST. */
    static ExposureProbeSpec altPortPost(String ruleId, String path, int port, String body) {
        return new ExposureProbeSpec(ruleId, List.of(path), "POST", body, port, false, false);
    }
}
