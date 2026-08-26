package org.freedonia.bloodhound.worker.modules.nuclei;

import java.util.List;

/** One matched result from nuclei's JSONL output - see NucleiResultParser. */
public record NucleiFinding(
        String templateId,
        String name,
        String severity,
        String description,
        String host,
        String matchedAt,
        String reference,
        List<String> extractedResults,
        String curlCommand,
        String cveId) {}
