package org.freedonia.bloodhound.server.mcp;

import jakarta.servlet.http.HttpServletRequest;
import java.security.Principal;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.HtmlUtils;

/**
 * Branded replacements for Spring Authorization Server's plain default login and consent pages -
 * see McpSecurityConfig's {@code .loginPage("/login")}/{@code .consentPage("/oauth2/consent")}
 * wiring. Both were left as Spring's stock, unstyled defaults for the first version of MCP support
 * ("functional, not styled" per this package's own earlier comments), which was a reasonable scope
 * cut back when self-registered clients could never actually complete the flow at all (see
 * ConsentRequiringRegisteredClientRepository - that gap is now fixed). Now that a real AI agent can
 * genuinely reach this screen, an unbranded, unstyled page at the exact moment a user is asked to
 * grant it access to their org's security data is a real trust/UX gap, not a cosmetic one.
 *
 * <p>Plain HTML strings, not a templating engine - central-server has no Thymeleaf dependency and
 * these are two small, mostly-static pages; adding a templating engine for this would be a bigger
 * footprint than the pages themselves. Self-contained (inline {@code <style>}, no external fonts or
 * scripts) so a strict CSP can be set directly on the response - see the {@code Content-Security-
 * Policy} header below, matching webui's own SecurityHeadersFilter precedent for exactly this
 * reasoning (a real, browser-rendered page this app serves getting the same header hygiene this
 * app itself flags as findings on other sites).
 */
@Controller
public class McpLoginConsentPageController {

    /** No external stylesheets/fonts/scripts referenced anywhere in either page below. */
    private static final String CSP = "default-src 'self'; "
            + "style-src 'self' 'unsafe-inline'; "
            + "script-src 'none'; "
            + "img-src 'self'; "
            + "object-src 'none'; "
            + "base-uri 'self'; "
            + "form-action 'self'; "
            + "frame-ancestors 'none'";

    private static final String STYLE = """
            <style>
              :root { color-scheme: dark; }
              body {
                margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
                background: #0a0a12; color: #cbd5e1;
                font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
              }
              .panel {
                width: 100%; max-width: 380px; margin: 24px; padding: 32px;
                background: rgba(18, 7, 31, 0.85); border: 1px solid rgba(0, 240, 255, 0.2);
                border-radius: 8px; box-shadow: 0 0 8px #00f0ff, 0 0 24px rgba(0, 240, 255, 0.35);
              }
              h1 {
                margin: 0 0 24px; text-align: center; font-size: 18px; font-weight: 700;
                letter-spacing: 0.15em; text-transform: uppercase; color: #00f0ff;
              }
              label {
                display: block; margin-bottom: 4px; font-size: 11px; text-transform: uppercase;
                letter-spacing: 0.1em; color: #94a3b8;
              }
              input[type=text], input[type=password], input[type=email] {
                width: 100%; box-sizing: border-box; margin-bottom: 16px; padding: 8px 12px;
                background: #0a0a12; border: 1px solid #334155; border-radius: 4px;
                color: #e2e8f0; font: inherit; font-size: 14px;
              }
              input:focus { outline: none; border-color: #00f0ff; }
              button {
                width: 100%; padding: 10px; border: none; border-radius: 4px; cursor: pointer;
                background: rgba(255, 46, 151, 0.9); color: #0a0a12; font: inherit; font-size: 14px;
                font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em;
              }
              button:hover { background: #ff2e97; }
              button.secondary {
                background: transparent; border: 1px solid #334155; color: #cbd5e1; margin-top: 10px;
              }
              button.secondary:hover { border-color: #64748b; }
              .error {
                margin: 0 0 16px; padding: 8px 12px; border-radius: 4px; font-size: 12px;
                background: rgba(255, 46, 151, 0.08); border: 1px solid rgba(255, 46, 151, 0.4); color: #ff2e97;
              }
              .hint { margin: 16px 0 0; font-size: 11px; color: #64748b; line-height: 1.5; }
              .scope-row {
                display: flex; align-items: center; gap: 8px; margin: 4px 0 20px;
                font-size: 13px; color: #e2e8f0;
              }
              .client-name { color: #00f0ff; font-weight: 700; word-break: break-word; }
              .account { color: #ff2e97; }
            </style>
            """;

    private final RegisteredClientRepository registeredClientRepository;

    public McpLoginConsentPageController(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    @GetMapping(value = "/login", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> login(
            @RequestParam(value = "error", required = false) String error, HttpServletRequest request) {
        CsrfToken csrf = csrfToken(request);
        String errorBanner = error != null
                ? "<p class=\"error\" role=\"alert\">Incorrect email or password.</p>"
                : "";
        String html =
                """
                <!doctype html>
                <html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Sign in - Bloodhound</title>
                %s
                </head><body>
                <div class="panel">
                  <h1>Sign in</h1>
                  %s
                  <form method="post" action="/login">
                    <input type="hidden" name="%s" value="%s">
                    <label for="username">Email</label>
                    <input id="username" name="username" type="email" required autofocus autocomplete="email">
                    <label for="password">Password</label>
                    <input id="password" name="password" type="password" required autocomplete="current-password">
                    <button type="submit">Sign in</button>
                  </form>
                  <p class="hint">Bloodhound MCP server sign-in - authorizing an AI agent to access your organization's data.</p>
                </div>
                </body></html>
                """
                        .formatted(
                                STYLE,
                                errorBanner,
                                HtmlUtils.htmlEscape(csrf.getParameterName()),
                                HtmlUtils.htmlEscape(csrf.getToken()));
        return htmlResponse(html);
    }

    @GetMapping(value = "/oauth2/consent", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> consent(
            @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
            @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
            @RequestParam(OAuth2ParameterNames.STATE) String state,
            Principal principal,
            HttpServletRequest request) {
        RegisteredClient client = registeredClientRepository.findByClientId(clientId);
        // clientName is attacker-controlled (Dynamic Client Registration accepts an arbitrary
        // client_name - see ConsentRequiringRegisteredClientRepository's own length cap). Shown
        // here so a user can tell what they're actually approving instead of a bare opaque
        // client_id (informed consent needs a recognizable name, not a random string) - but that
        // only holds if it's rendered as inert text, hence htmlEscape rather than the naive
        // string-concatenation this file uses for its otherwise-static markup.
        String clientLabel = client != null && client.getClientName() != null
                ? HtmlUtils.htmlEscape(client.getClientName())
                : HtmlUtils.htmlEscape(clientId);
        CsrfToken csrf = csrfToken(request);

        StringBuilder scopeRows = new StringBuilder();
        for (String s : scope.split(" ")) {
            if (s.isBlank()) continue;
            String escaped = HtmlUtils.htmlEscape(s);
            scopeRows
                    .append("<div class=\"scope-row\"><input type=\"checkbox\" id=\"scope-")
                    .append(escaped)
                    .append("\" name=\"scope\" value=\"")
                    .append(escaped)
                    .append("\" checked><label for=\"scope-")
                    .append(escaped)
                    .append("\" style=\"display:inline;margin:0;text-transform:none;letter-spacing:normal;font-size:13px;color:#e2e8f0;\">")
                    .append(escaped)
                    .append("</label></div>");
        }

        String html =
                """
                <!doctype html>
                <html lang="en"><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Authorize access - Bloodhound</title>
                %s
                </head><body>
                <div class="panel">
                  <h1>Authorize access</h1>
                  <p style="font-size:13px;line-height:1.6;">
                    <span class="client-name">%s</span> wants to access
                    <span class="account">%s</span>'s Bloodhound data.
                  </p>
                  <form method="post" action="/oauth2/authorize">
                    <input type="hidden" name="%s" value="%s">
                    <input type="hidden" name="client_id" value="%s">
                    <input type="hidden" name="state" value="%s">
                    %s
                    <button type="submit" id="submit-consent">Authorize</button>
                    <button type="button" class="secondary" id="cancel-consent" onclick="document.forms[0].reset();document.forms[0].querySelectorAll('input[type=checkbox]').forEach(c=>c.checked=false);document.forms[0].submit();">Cancel</button>
                  </form>
                  <p class="hint">Read-only access - this AI agent can view findings, targets, subdomains, and scan runs. Nothing can be changed. Revoke this at any time from Admin - MCP Server.</p>
                </div>
                </body></html>
                """
                        .formatted(
                                STYLE,
                                clientLabel,
                                HtmlUtils.htmlEscape(principal.getName()),
                                HtmlUtils.htmlEscape(csrf.getParameterName()),
                                HtmlUtils.htmlEscape(csrf.getToken()),
                                HtmlUtils.htmlEscape(clientId),
                                HtmlUtils.htmlEscape(state),
                                scopeRows);
        return htmlResponse(html);
    }

    private static ResponseEntity<String> htmlResponse(String html) {
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .header("Content-Security-Policy", CSP)
                .header("Referrer-Policy", "no-referrer")
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .body(html);
    }

    /** CsrfFilter always exposes the current token under this well-known request-attribute name,
     * the same mechanism raw HTML forms (no templating engine) are expected to read it from -
     * confirmed live against Spring's own generated default login form, which set the identical
     * {@code name="_csrf"} hidden field this replaces. */
    private static CsrfToken csrfToken(HttpServletRequest request) {
        return (CsrfToken) request.getAttribute(CsrfToken.class.getName());
    }
}
