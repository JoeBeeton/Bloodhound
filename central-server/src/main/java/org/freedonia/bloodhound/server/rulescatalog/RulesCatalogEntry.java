package org.freedonia.bloodhound.server.rulescatalog;

import java.math.BigDecimal;

public record RulesCatalogEntry(
        String ruleId,
        String category,
        String defaultSeverity,
        String title,
        String description,
        String remediationAdvice,
        BigDecimal weight,
        boolean enabled) {}
