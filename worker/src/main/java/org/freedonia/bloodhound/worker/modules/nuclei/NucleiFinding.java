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
        String cveId,
        /** Which of a template's several named matchers actually fired - null for a template with
         * only one, unnamed matcher. Several templates (waf-detect chief among them - its "name"
         * field per matcher is literally the WAF vendor, e.g. "cloudflare") only distinguish what
         * was actually found via this field, not template-id alone. */
        String matcherName) {}
