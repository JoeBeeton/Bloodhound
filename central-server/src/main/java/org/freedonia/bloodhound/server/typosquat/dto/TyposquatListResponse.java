package org.freedonia.bloodhound.server.typosquat.dto;

import java.util.List;

/**
 * realDomainHasScreenshot tells the frontend whether it's worth requesting
 * GET .../typosquats/real-domain-screenshot at all, the same "has a
 * screenshot" pattern each {@link TyposquatCandidateSummary} already carries
 * for its own candidate thumbnail.
 */
public record TyposquatListResponse(boolean realDomainHasScreenshot, List<TyposquatCandidateSummary> candidates) {}
