package org.freedonia.bloodhound.server.jobqueue.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.server.findings.FindingPayload;

/**
 * A security review found no bound at all on findings/rawMetadata/logLines - combined with the
 * worker-result authorization gap fixed in JobLifecycleService (a stolen shared WORKER_API_KEY
 * could previously ingest against any job by id, real claim or not), an unbounded findings list
 * or evidence map was a way to write an effectively unlimited amount of arbitrary JSONB into
 * Postgres in a single request. Tomcat's own default max-swallow-size (2MB) already put an
 * implicit outer bound on the raw request body, but that's a container default, not a deliberate
 * application-level limit - these caps are explicit and generous relative to any real scan
 * module's actual output (a full-corpus nuclei run - this app's most finding-dense module by far -
 * produces well under 500 findings against a real target in practice).
 */
public record JobResultRequest(
        @NotBlank String workerId,
        @Valid @Size(max = 2000) List<FindingPayload> findings,
        @Size(max = 500) Map<String, Object> rawMetadata,
        @Size(max = 5000) List<String> logLines) {}
