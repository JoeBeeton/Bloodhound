package org.freedonia.bloodhound.worker.modules.subdomain;

import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Passive subdomain enumeration via ProjectDiscovery's subfinder binary
 * (installed in the worker image; see Dockerfile). Verified against
 * subfinder v2.15.0's actual flag set: it is passive-only by default (no
 * active brute-forcing occurs unless you explicitly pass -active/-nW, which
 * this source never does) - there is no "-passive" flag, it doesn't exist,
 * passive is simply the default behaviour. "-timeout 30" bounds how long any
 * single upstream source query waits; ExternalCliSubdomainSource's own
 * process-level hard timeout is the real backstop.
 */
@Component
public class SubfinderCliSource extends ExternalCliSubdomainSource {

    @Override
    protected List<String> command(String rootDomain) {
        return List.of("subfinder", "-d", rootDomain, "-silent", "-timeout", "30");
    }

    @Override
    protected List<String> parseOutput(String stdout) {
        return parse(stdout);
    }

    /** Pure: one hostname per line, tolerant of blank/trailing lines. */
    static List<String> parse(String stdout) {
        if (stdout == null || stdout.isBlank()) {
            return List.of();
        }
        List<String> hostnames = new ArrayList<>();
        for (String line : stdout.split("\\R")) {
            String trimmed = line.trim().toLowerCase();
            if (!trimmed.isEmpty()) {
                hostnames.add(trimmed);
            }
        }
        return hostnames;
    }

    @Override
    public String sourceName() {
        return "SUBFINDER";
    }
}
