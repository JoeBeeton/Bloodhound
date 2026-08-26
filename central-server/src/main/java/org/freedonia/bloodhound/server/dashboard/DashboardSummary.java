package org.freedonia.bloodhound.server.dashboard;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.dto.OrgFindingSummary;
import org.freedonia.bloodhound.server.target.dto.TargetSummary;

/** The org-overview aggregate the dashboard renders in one round trip: own-domain hero cards, top findings, recent activity, stat tiles. */
public record DashboardSummary(
        List<TargetSummary> ownTargets,
        List<OrgFindingSummary> topFindings,
        List<RecentActivity> recentActivity,
        Stats stats) {

    public record RecentActivity(
            UUID id, UUID targetId, String targetHostname, String status, Instant startedAt, Instant completedAt) {}

    public record Stats(
            int totalTargets,
            int ownCount,
            int competitorCount,
            int watchlistCount,
            int openCriticalCount,
            int openHighCount) {}
}
