package org.freedonia.bloodhound.worker.modules.breach;

import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Default (and, for now, only) BreachCorrelationSource: always reports no
 * records. BreachCorrelationModule never even calls this when HIBP_API_KEY
 * is unset (the common case), so in practice this class exists mainly to
 * give Spring something to inject and to document the extension point - a
 * real provider (e.g. Have I Been Pwned's paid domain-search API) would be
 * added as a second @Component implementing BreachCorrelationSource, wired
 * in alongside or in place of this one.
 */
@Component
public class NoOpBreachCorrelationSource implements BreachCorrelationSource {

    @Override
    public List<BreachRecord> lookup(String domain) {
        return List.of();
    }
}
