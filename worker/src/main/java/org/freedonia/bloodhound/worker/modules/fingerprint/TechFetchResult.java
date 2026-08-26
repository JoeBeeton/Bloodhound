package org.freedonia.bloodhound.worker.modules.fingerprint;

import java.util.List;
import java.util.Map;

/** Raw fetch output for one hostname - headers keyed lowercase, body capped for signature matching. */
public record TechFetchResult(Map<String, String> headers, List<String> setCookieHeaders, String body) {}
