package org.freedonia.bloodhound.worker.modules.breach;

import java.time.Instant;
import java.util.List;

/**
 * One provider of breach-correlation data for a domain (e.g. Have I Been
 * Pwned's domain search). No implementation of this interface ships in
 * Bloodhound - see NoOpBreachCorrelationSource and BreachCorrelationModule
 * for why, and for how an operator would plug a real one in.
 */
public interface BreachCorrelationSource {

    List<BreachRecord> lookup(String domain) throws Exception;

    record BreachRecord(String breachName, String description, Instant breachDate) {}
}
