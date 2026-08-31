package org.freedonia.bloodhound.server.jobqueue;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.swagger.v3.oas.annotations.Hidden;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.FindingPayload;
import org.freedonia.bloodhound.server.jobqueue.dto.ClaimJobsRequest;
import org.freedonia.bloodhound.server.jobqueue.dto.ClaimedJobDto;
import org.freedonia.bloodhound.server.jobqueue.dto.JobFailRequest;
import org.freedonia.bloodhound.server.jobqueue.dto.JobResultRequest;
import org.freedonia.bloodhound.server.jobqueue.dto.WorkerScopedRequest;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Worker-facing job queue endpoints - see SecurityConfig, these require ROLE_WORKER
 * (X-Worker-Api-Key), not a user JWT.
 *
 * <p>{@code @Hidden} - a security review found the public, unauthenticated /v3/api-docs (see
 * OpenApiConfig; SecurityConfig permitAlls that path) fully documented this internal worker
 * protocol - exact request/response shapes for job claiming/reporting - to anyone on the internet
 * with zero cost. Unlike every other controller OpenApiConfig's own javadoc deliberately keeps
 * documented (a genuine "map of the whole REST API" for a real customer, even one whose own
 * credential can't reach every operation - see e.g. admin-only routes, still worth documenting
 * for an ADMIN-role customer), X-Worker-Api-Key is purely an infrastructure secret this app's own
 * worker fleet uses - no real customer is ever issued one or has any reason to read this
 * protocol's docs. Hiding it removes pure attacker reconnaissance value with no loss to any
 * legitimate consumer of the spec.
 */
@Hidden
@RestController
@RequestMapping("/api/v1/jobs")
public class JobController {

    private final JobClaimService jobClaimService;
    private final JobLifecycleService jobLifecycleService;
    private final TargetRepository targetRepository;
    private final ObjectMapper objectMapper;

    public JobController(
            JobClaimService jobClaimService,
            JobLifecycleService jobLifecycleService,
            TargetRepository targetRepository,
            ObjectMapper objectMapper) {
        this.jobClaimService = jobClaimService;
        this.jobLifecycleService = jobLifecycleService;
        this.targetRepository = targetRepository;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/claim")
    public List<ClaimedJobDto> claim(@Valid @RequestBody ClaimJobsRequest request) {
        return jobClaimService.claim(request.workerId(), request.capacity()).stream()
                .map(job -> new ClaimedJobDto(
                        job.id(),
                        job.targetId(),
                        targetRepository.findById(job.targetId()).map(t -> t.hostname()).orElse(""),
                        job.scanRunId(),
                        job.moduleType(),
                        parseJsonObject(job.payloadJson())))
                .toList();
    }

    @PatchMapping("/{id}/heartbeat")
    public ResponseEntity<Void> heartbeat(@PathVariable UUID id, @Valid @RequestBody WorkerScopedRequest request) {
        jobLifecycleService.heartbeat(id, request.workerId());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/result")
    public ResponseEntity<Void> result(@PathVariable UUID id, @Valid @RequestBody JobResultRequest request) {
        List<FindingPayload> findings = request.findings() == null ? List.of() : request.findings();
        Map<String, Object> rawMetadata = request.rawMetadata() == null ? Map.of() : request.rawMetadata();
        Map<String, Object> resultMetadata = Map.of("findingCount", findings.size(), "rawMetadata", rawMetadata);
        jobLifecycleService.result(id, request.workerId(), writeJson(resultMetadata), findings, rawMetadata, request.logLines());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/{id}/fail")
    public ResponseEntity<Void> fail(@PathVariable UUID id, @Valid @RequestBody JobFailRequest request) {
        jobLifecycleService.fail(id, request.workerId(), request.errorDetail(), request.logLines());
        return ResponseEntity.noContent().build();
    }

    private Map<String, Object> parseJsonObject(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("corrupt job payload json", e);
        }
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("failed to serialize job result", e);
        }
    }
}
