package org.freedonia.bloodhound.server.eol;

import java.util.UUID;

/** One (target, hostname) currently fingerprinted running a technology/version this feature knows how to check against endoflife.date - the input to matching, before we know whether it's actually EOL/approaching. */
public record EolCandidate(UUID targetId, String hostname, String technologyName, String version) {}
