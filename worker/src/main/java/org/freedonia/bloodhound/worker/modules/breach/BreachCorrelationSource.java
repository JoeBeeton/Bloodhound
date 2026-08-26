package org.freedonia.bloodhound.worker.modules.breach;

import java.time.Instant;
import java.util.List;

/**
 * One provider of breach-correlation data for a domain. {@link
 * HibpBreachCorrelationSource} (Have I Been Pwned) is the real
 * implementation that ships; {@link NoOpBreachCorrelationSource} is the
 * inert fallback - see both, and {@link BreachCorrelationModule}, for how
 * they fit together.
 */
public interface BreachCorrelationSource {

    List<BreachRecord> lookup(String domain) throws Exception;

    record BreachRecord(String breachName, String description, Instant breachDate) {}
}
