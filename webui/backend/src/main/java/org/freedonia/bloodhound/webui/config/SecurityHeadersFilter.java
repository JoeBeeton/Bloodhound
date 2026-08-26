package org.freedonia.bloodhound.webui.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.stereotype.Component;

/**
 * webui-backend has no Spring Security dependency (it's a static-asset host
 * plus two thin proxies, not an authorization boundary of its own), so it
 * gets none of the response headers Spring Security adds by default on
 * central-server (X-Content-Type-Options, X-Frame-Options, etc. - confirmed
 * present there via `curl -I localhost:8080/healthz`). But webui is what the
 * browser actually talks to, so it's webui's headers - not central-server's -
 * that determine whether this app is protected against clickjacking or has
 * any CSP at all; confirmed via `curl -I localhost:8090/` that it currently
 * has none. Bloodhound flags exactly these headers as findings (HEADER_XFO_
 * MISSING, HEADER_CSP_MISSING, etc.) when scanning other sites - shipping the
 * same gap on its own login page would be a real, and slightly embarrassing,
 * miss. This is a hand-rolled filter rather than pulling in Spring Security
 * for the sole purpose of its header defaults.
 */
@Component
public class SecurityHeadersFilter extends HttpFilter {

    // No external script/style/font/image hosts are used anywhere in this
    // app (confirmed: no CDN links in index.html, Tailwind/fonts are
    // bundled) - so this can be genuinely restrictive rather than a
    // wildcard placeholder. 'unsafe-inline' on style-src is needed for
    // Vite/Tailwind's injected <style> tags; nothing here allows inline
    // *script*.
    //
    // This filter also sets Cache-Control. Without it, browsers apply
    // their own heuristic freshness rules to index.html (which has no
    // content hash in its URL, unlike /assets/**), and have been
    // observed in practice serving a stale copy - including a stale
    // reference to an old, already-replaced /assets/*.js bundle - for a
    // long time after a redeploy, with no way for the user to tell a
    // reload wouldn't help short of a hard refresh. /assets/** is
    // Vite's content-hashed build output (a new build produces new
    // filenames), so those are safe to cache aggressively/immutably;
    // everything else (index.html, and every SPA route
    // SpaFallbackController forwards to it) must always revalidate.
    private static final String CSP = "default-src 'self'; "
            + "script-src 'self'; "
            + "style-src 'self' 'unsafe-inline'; "
            + "img-src 'self' data:; "
            + "connect-src 'self'; "
            + "font-src 'self'; "
            + "object-src 'none'; "
            + "base-uri 'self'; "
            + "frame-ancestors 'none'";

    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        response.setHeader("Permissions-Policy", "geolocation=(), microphone=(), camera=()");
        response.setHeader("Content-Security-Policy", CSP);
        // Harmless no-op over plain HTTP (as in local dev); becomes real HSTS
        // once this is served over TLS in production.
        response.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");

        if (request.getRequestURI().startsWith("/assets/")) {
            response.setHeader("Cache-Control", "public, max-age=31536000, immutable");
        } else {
            response.setHeader("Cache-Control", "no-cache");
        }

        chain.doFilter(request, response);
    }
}
