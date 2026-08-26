package org.freedonia.bloodhound.server.compare.dto;

import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.scoring.dto.ScoreSnapshotSummary;
import org.freedonia.bloodhound.server.target.Target;

/** One target's score history, shaped for direct use as one series in a multi-line trend chart. */
public record CompareSeries(UUID targetId, String hostname, String targetType, List<ScoreSnapshotSummary> history) {

    public static CompareSeries of(Target target, List<ScoreSnapshotSummary> history) {
        return new CompareSeries(target.id(), target.hostname(), target.targetType(), history);
    }
}
