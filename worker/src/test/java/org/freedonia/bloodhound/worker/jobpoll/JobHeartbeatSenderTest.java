package org.freedonia.bloodhound.worker.jobpoll;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.UUID;
import org.freedonia.bloodhound.worker.jobpoll.dto.WorkerScopedRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

/**
 * The periodic heartbeat: fires roughly once per configured interval while a
 * handle is open, and genuinely stops firing after {@code stop()} - both
 * real, observable scheduling behavior, not just wiring. Uses a short real
 * interval (no mocked clock/Awaitility - neither is a declared test
 * dependency of this module) and polls for the effect with plain sleeps,
 * tolerant of timing jitter the way scheduled-executor tests generally have
 * to be.
 */
class JobHeartbeatSenderTest {

    private final RestClient centralServerClient = mock(RestClient.class);
    private final RestClient.RequestBodyUriSpec uriSpec = mock(RestClient.RequestBodyUriSpec.class);
    private final RestClient.RequestBodySpec bodySpec = mock(RestClient.RequestBodySpec.class);
    private final RestClient.ResponseSpec responseSpec = mock(RestClient.ResponseSpec.class);

    private void wireHeartbeatChain() {
        when(centralServerClient.patch()).thenReturn(uriSpec);
        when(uriSpec.uri(any(String.class), any(Object.class))).thenReturn(bodySpec);
        when(bodySpec.body(any(WorkerScopedRequest.class))).thenReturn(bodySpec);
        when(bodySpec.retrieve()).thenReturn(responseSpec);
        when(responseSpec.toBodilessEntity()).thenReturn(ResponseEntity.ok().build());
    }

    /** Polls until {@code condition} is true or the deadline passes, instead of one fixed sleep - keeps the test fast on a quiet machine and still reliable under load. */
    private void awaitUntil(long timeoutMs, java.util.function.BooleanSupplier condition) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (condition.getAsBoolean()) {
                return;
            }
            Thread.sleep(15);
        }
        assertThat(condition.getAsBoolean()).as("condition never became true within %dms", timeoutMs).isTrue();
    }

    @Test
    void start_sendsHeartbeatOnEveryInterval_forTheGivenJob() throws InterruptedException {
        wireHeartbeatChain();
        JobHeartbeatSender sender = new JobHeartbeatSender(centralServerClient, "worker-1", 20);
        UUID jobId = UUID.randomUUID();

        JobHeartbeatSender.Handle handle = sender.start(jobId);
        try {
            awaitUntil(2000, () -> mockingDetails(centralServerClient).getInvocations().size() >= 2);
            verify(uriSpec, org.mockito.Mockito.atLeast(2)).uri(eq("/api/v1/jobs/{id}/heartbeat"), eq(jobId));
        } finally {
            handle.stop();
        }
    }

    @Test
    void stop_haltsFurtherHeartbeats() throws InterruptedException {
        wireHeartbeatChain();
        JobHeartbeatSender sender = new JobHeartbeatSender(centralServerClient, "worker-1", 20);
        UUID jobId = UUID.randomUUID();

        JobHeartbeatSender.Handle handle = sender.start(jobId);
        awaitUntil(2000, () -> !mockingDetails(centralServerClient).getInvocations().isEmpty());
        handle.stop();

        int countAtStop = mockingDetails(centralServerClient).getInvocations().size();
        Thread.sleep(200);
        int countAfterWaiting = mockingDetails(centralServerClient).getInvocations().size();

        assertThat(countAfterWaiting).isEqualTo(countAtStop);
    }

    @Test
    void sendFailure_doesNotThrow_heartbeatLoopKeepsRunning() throws InterruptedException {
        when(centralServerClient.patch()).thenThrow(new RuntimeException("central-server unreachable"));
        JobHeartbeatSender sender = new JobHeartbeatSender(centralServerClient, "worker-1", 20);
        UUID jobId = UUID.randomUUID();

        JobHeartbeatSender.Handle handle = sender.start(jobId);
        try {
            awaitUntil(2000, () -> mockingDetails(centralServerClient).getInvocations().size() >= 2);
            verify(centralServerClient, org.mockito.Mockito.atLeast(2)).patch();
        } finally {
            handle.stop();
        }
    }

    @Test
    void stop_isSafeToCallMultipleTimes() {
        wireHeartbeatChain();
        JobHeartbeatSender sender = new JobHeartbeatSender(centralServerClient, "worker-1", 5000);
        JobHeartbeatSender.Handle handle = sender.start(UUID.randomUUID());

        handle.stop();
        handle.stop();
    }
}
