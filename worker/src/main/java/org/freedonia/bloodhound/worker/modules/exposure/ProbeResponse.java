package org.freedonia.bloodhound.worker.modules.exposure;

/** body is capped at ExposedPathFetcher.BODY_LIMIT_BYTES and is always "" for skipBody probes (heapdump). */
public record ProbeResponse(int status, String contentType, Long contentLength, String body) {

    static ProbeResponse unreachable() {
        return new ProbeResponse(-1, null, null, null);
    }

    boolean isReachable() {
        return status >= 0;
    }
}
