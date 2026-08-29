package org.freedonia.bloodhound.webui.spa;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Forwards client-side (React Router) routes to index.html so a direct
 * navigation or browser refresh on e.g. /dashboard doesn't 404. Spring
 * Boot's default static-resource handling only serves index.html at the
 * exact root path, not for arbitrary client routes. Excludes /api/** (real
 * backend routes) and /assets/** (the Vite build output) so those still
 * fall through to their normal handlers.
 *
 * <p>The exclusion requires an EXACT segment match ({@code api$|assets$}),
 * not just a string prefix - a bare {@code (?!api|assets)} would also
 * reject any route that merely starts with those letters (e.g. a
 * hypothetical {@code /api-keys} instead of the real {@code
 * /settings/api-keys}, or {@code /assets-inventory}), silently 404ing on
 * direct navigation/refresh even though it has nothing to do with the
 * real {@code /api/**}/{@code /assets/**} namespaces. {@code {path:...}}
 * only ever captures a single path segment regardless of what the regex
 * itself would allow, so no separate "/"-boundary check is needed - and
 * Spring's PathPattern regex parser (stricter than plain java.util.regex)
 * rejects an extra {@code (?:...)} grouping here, so this stays as one
 * lookahead with a plain alternation, the same shape as the original.
 * Caught via a live Playwright sweep hitting a guessed (wrong, but
 * plausible-looking) URL - confirmed no current frontend route actually
 * triggers the old bug, but the regex itself was still wrong.
 */
@Controller
public class SpaFallbackController {

    @GetMapping({"/{path:^(?!api$|assets$)[^.]*$}", "/{path:^(?!api$|assets$)[^.]*$}/**"})
    public String forwardToIndex() {
        return "forward:/index.html";
    }
}
