package org.freedonia.bloodhound.worker.modules.breach;

import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Always reports no records. {@link HibpBreachCorrelationSource} (marked
 * {@code @Primary}) is the one actually wired into
 * {@link BreachCorrelationModule} now, but this class stays as the fallback
 * Spring bean of last resort and as a reference for what implementing this
 * interface from scratch looks like - genuinely still relevant if this
 * project's HIBP subscription/domain-verification ever lapses, or for
 * anyone plugging in a different breach-data provider entirely.
 * BreachCorrelationModule never even calls whichever implementation is
 * wired in when HIBP_API_KEY is unset (the common case), so this class is
 * inert either way in that configuration.
 */
@Component
public class NoOpBreachCorrelationSource implements BreachCorrelationSource {

    @Override
    public List<BreachRecord> lookup(String domain) {
        return List.of();
    }
}
