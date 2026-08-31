package org.freedonia.bloodhound.server.compare;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.scoring.ScoreSnapshotRepository;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class CompareControllerTest {

    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final ScoreSnapshotRepository scoreSnapshotRepository = mock(ScoreSnapshotRepository.class);
    private final CompareController controller = new CompareController(targetRepository, scoreSnapshotRepository);

    private final UUID orgId = UUID.randomUUID();
    private final JwtPrincipal principal = new JwtPrincipal(UUID.randomUUID(), orgId, "VIEWER", "u@example.com");

    private Target target(UUID id) {
        return new Target(id, orgId, "host-" + id, "OWN", "AUTHORIZED", 86400, Instant.now(), true, Instant.now(), null);
    }

    @Test
    void tooManyTargetIds_rejected_neverQueriesAnyRepository() {
        // An input-validation review found this had no bound at all - a crafted request with a
        // very long targetIds list would drive a proportionally long chain of sequential
        // findByIdAndOrganization + score-history lookups, one pair per id.
        List<UUID> tooMany = Stream.generate(UUID::randomUUID).limit(21).toList();

        assertThatThrownBy(() -> controller.compare(tooMany, null, null, principal))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(400));
        verify(targetRepository, never()).findByIdAndOrganization(any(), any());
        verify(scoreSnapshotRepository, never()).findHistory(any(), any(), any());
    }

    @Test
    void withinBound_stillReturnsASeriesPerTarget() {
        UUID id1 = UUID.randomUUID();
        UUID id2 = UUID.randomUUID();
        when(targetRepository.findByIdAndOrganization(id1, orgId)).thenReturn(Optional.of(target(id1)));
        when(targetRepository.findByIdAndOrganization(id2, orgId)).thenReturn(Optional.of(target(id2)));
        when(scoreSnapshotRepository.findHistory(any(), any(), any())).thenReturn(List.of());

        var result = controller.compare(List.of(id1, id2), null, null, principal);

        assertThat(result).hasSize(2);
    }
}
