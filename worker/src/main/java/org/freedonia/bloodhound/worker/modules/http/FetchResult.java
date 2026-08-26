package org.freedonia.bloodhound.worker.modules.http;

import java.util.List;
import java.util.Map;

/** Raw fetch output for one hostname - headers keyed lowercase, first value each; raw Set-Cookie lines kept intact for the parser. */
public record FetchResult(boolean https, Map<String, String> headers, List<String> setCookieHeaders) {}
