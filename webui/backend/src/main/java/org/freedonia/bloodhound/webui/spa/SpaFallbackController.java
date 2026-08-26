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
 */
@Controller
public class SpaFallbackController {

    @GetMapping({"/{path:^(?!api|assets)[^.]*$}", "/{path:^(?!api|assets)[^.]*$}/**"})
    public String forwardToIndex() {
        return "forward:/index.html";
    }
}
