package org.freedonia.bloodhound.server.subdomain;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.subdomain.dto.SubdomainSummary;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
public class SubdomainController {

    /** Generous enough for the overwhelming majority of targets to see everything in one request, without ever risking the multi-MB/multi-second response a truly unbounded query could produce. */
    private static final int DEFAULT_LIMIT = 200;
    private static final int MAX_LIMIT = 500;

    /** Same reasoning as FindingController#MAX_EXPORT_LIMIT - comfortably above the largest real subdomain count seen in this deployment (57,107 for one target), while still bounding the export response. */
    private static final int MAX_EXPORT_LIMIT = 100_000;

    private final SubdomainRepository subdomainRepository;
    private final TargetRepository targetRepository;

    public SubdomainController(SubdomainRepository subdomainRepository, TargetRepository targetRepository) {
        this.subdomainRepository = subdomainRepository;
        this.targetRepository = targetRepository;
    }

    /**
     * Response body shape is unchanged (a bare JSON array) to keep every
     * existing frontend caller working - the total count (which can be far
     * larger than what's actually returned) is carried in the X-Total-Count
     * header instead, so callers that only need "show me some subdomains"
     * don't have to change at all, and ones that need to page through
     * everything can read the header to know when to stop.
     */
    @GetMapping("/api/v1/targets/{id}/subdomains")
    public ResponseEntity<List<SubdomainSummary>> list(
            @PathVariable UUID id,
            @RequestParam(required = false) String hostname,
            @RequestParam(defaultValue = "" + DEFAULT_LIMIT) int limit,
            @RequestParam(defaultValue = "0") int offset,
            @AuthenticationPrincipal JwtPrincipal principal) {
        targetRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        int boundedLimit = Math.clamp(limit, 1, MAX_LIMIT);
        int boundedOffset = Math.max(offset, 0);

        List<SubdomainSummary> page = subdomainRepository.findByTarget(id, hostname, boundedLimit, boundedOffset).stream()
                .map(SubdomainSummary::from)
                .toList();
        int totalCount = subdomainRepository.countByTarget(id, hostname);

        return ResponseEntity.ok().header("X-Total-Count", String.valueOf(totalCount)).body(page);
    }

    /**
     * A product review found no way to export a target's discovered subdomains anywhere, despite
     * findings and the audit log both having a CSV export already - the subdomain list is the
     * actual asset inventory this tool exists to produce, and a user handing it off to another
     * tool (a CMDB, a separate scanner's target list) had no way to get it out except manually
     * copying rows off the paginated table. Respects the same hostname filter as {@link #list}.
     */
    @GetMapping(value = "/api/v1/targets/{id}/subdomains/export", produces = "text/csv")
    public ResponseEntity<byte[]> export(
            @PathVariable UUID id,
            @RequestParam(required = false) String hostname,
            @AuthenticationPrincipal JwtPrincipal principal) {
        Target target = targetRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        List<SubdomainSummary> subdomains = subdomainRepository.findByTarget(id, hostname, MAX_EXPORT_LIMIT, 0).stream()
                .map(SubdomainSummary::from)
                .toList();
        byte[] csv = SubdomainCsvWriter.write(subdomains).getBytes(StandardCharsets.UTF_8);
        String filename = sanitizeFilename(target.hostname()) + "-subdomains-" + LocalDate.now() + ".csv";
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/csv;charset=UTF-8"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .body(csv);
    }

    /** hostname is user-supplied at target creation - strip anything that could break a quoted Content-Disposition filename. */
    private static String sanitizeFilename(String hostname) {
        return hostname.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    /**
     * Single-hostname lookup for the subdomain-detail page - deliberately
     * not "fetch the paginated list and find it client-side" (what this
     * page used to do): a subdomain outside whatever page {@link #list}
     * happens to return would otherwise silently fail to load on its own
     * detail page for any target with more than {@code limit} subdomains.
     */
    @GetMapping("/api/v1/targets/{id}/subdomains/{hostname}")
    public SubdomainSummary get(
            @PathVariable UUID id, @PathVariable String hostname, @AuthenticationPrincipal JwtPrincipal principal) {
        targetRepository
                .findByIdAndOrganization(id, principal.organizationId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        return subdomainRepository
                .findByTargetAndHostname(id, hostname)
                .map(SubdomainSummary::from)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }
}
