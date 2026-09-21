package org.freedonia.bloodhound.server.eol;

import java.time.LocalDate;

/** One release cycle of a product, as reported by endoflife.date - e.g. nginx's "1.24" cycle. */
public record EolRelease(
        String releaseCycle, boolean isEol, LocalDate eolFrom, boolean isMaintained, String latestVersionInCycle) {}
