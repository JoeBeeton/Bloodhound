package org.freedonia.bloodhound.worker.modules.exposure;

/**
 * body is capped at ExposedPathFetcher.BODY_LIMIT_BYTES and is always "" for skipBody probes
 * (heapdump). {@code url} is the exact request URL this response came from - null only for
 * {@link #unreachable()}, since every real probe attempt knows the URL it just tried regardless
 * of outcome. Carried through to {@link ExposedPathDecisionLogic}'s evidence so a finding points
 * at exactly where it was found, not just "this hostname, somewhere".
 */
public record ProbeResponse(int status, String contentType, Long contentLength, String body, String url) {

    /** Test convenience - production code always knows (and passes) the URL it just probed. */
    ProbeResponse(int status, String contentType, Long contentLength, String body) {
        this(status, contentType, contentLength, body, null);
    }

    static ProbeResponse unreachable() {
        return new ProbeResponse(-1, null, null, null, null);
    }

    boolean isReachable() {
        return status >= 0;
    }
}
