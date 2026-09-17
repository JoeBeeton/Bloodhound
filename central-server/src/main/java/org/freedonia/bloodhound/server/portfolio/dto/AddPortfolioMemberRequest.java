package org.freedonia.bloodhound.server.portfolio.dto;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record AddPortfolioMemberRequest(@NotNull UUID targetId) {}
