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

    /**
     * A Slack incoming-webhook URL is a bearer secret, not an identifier - anyone who has it can
     * post arbitrary messages to that channel (a real phishing/social-engineering vector: a
     * message that looks exactly like it came from Bloodhound's own alerts). A product/AppSec
     * review found the API returned this in full on every GET, and the admin UI pre-filled it
     * into a plain visible text input every time the page loaded - on screen during any
     * screen-share, in browser form-autofill history, indefinitely. This keeps enough of the
     * path (team + webhook ID, path segments 1-2 of .../services/T.../B.../xxx) for an admin to
     * recognize *which* integration is configured, while redacting the actual secret segment
     * that would let someone post as it.
     */
    public static String mask(String url) {
        if (url == null) {
            return null;
        }
        try {
            URI uri = new URI(url);
            String path = uri.getPath();
            if (path == null) {
                return REDACTED_FALLBACK;
            }
            String[] segments = path.split("/");
            // segments[0] is "" (leading slash), [1] "services", [2] team id, [3] webhook id, [4] secret.
            if (segments.length < 5) {
                return REDACTED_FALLBACK;
            }
            return "https://" + REQUIRED_HOST + "/services/" + segments[2] + "/" + segments[3] + "/••••••••";
        } catch (URISyntaxException e) {
            return REDACTED_FALLBACK;
        }
    }

    private static final String REDACTED_FALLBACK = "https://" + REQUIRED_HOST + "/services/••••••••";
}
