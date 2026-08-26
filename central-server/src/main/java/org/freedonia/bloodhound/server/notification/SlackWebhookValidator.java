package org.freedonia.bloodhound.server.notification;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * An admin-configurable "webhook URL" that Bloodhound's own server later POSTs to is
 * an open server-side-request primitive unless the destination is constrained - the
 * same class of issue the recent security review hardened for scan targets
 * (SafeAddressValidator). Slack webhooks are always https://hooks.slack.com/services/...,
 * so this rejects anything else outright rather than trying to generically distinguish
 * "safe" from "unsafe" arbitrary URLs.
 *
 * <p>Uses {@link URI#getHost()} (not string prefix/contains checks) specifically so
 * host-confusion tricks don't slip through - "https://hooks.slack.com.evil.com/x" has
 * host "hooks.slack.com.evil.com" (rejected, not a prefix match), "https://evil.com/hooks.slack.com/x"
 * has host "evil.com" (rejected), and userinfo tricks like "https://hooks.slack.com@evil.com/x"
 * resolve to host "evil.com" under RFC 3986 (rejected) - getHost() already strips userinfo
 * correctly, which a naive substring check would not.
 */
public final class SlackWebhookValidator {

    private static final String REQUIRED_HOST = "hooks.slack.com";

    private SlackWebhookValidator() {}

    public static boolean isValid(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }
        try {
            URI uri = new URI(url);
            return "https".equals(uri.getScheme())
                    && REQUIRED_HOST.equals(uri.getHost())
                    && uri.getPath() != null
                    && uri.getPath().startsWith("/services/");
        } catch (URISyntaxException e) {
            return false;
        }
    }
}
