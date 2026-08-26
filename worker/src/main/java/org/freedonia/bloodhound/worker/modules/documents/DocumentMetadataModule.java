package org.freedonia.bloodhound.worker.modules.documents;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.freedonia.bloodhound.worker.modules.common.HostFanOut;
import org.freedonia.bloodhound.worker.modules.common.PayloadSubdomains;
import org.springframework.stereotype.Component;

/**
 * Tier 1: fetches each host's homepage (root plus known subdomains - see
 * {@link HostFanOut}), extracts any linked PDF/Office documents (bounded,
 * see {@link DocumentLinkDecisionLogic}), downloads each (bounded, see
 * {@link DocumentFetcher}), and parses embedded author/editor metadata (see
 * {@link DocumentMetadataParser}) - a classic passive OSINT technique
 * distinct from every other Tier 1 module: it looks inside a document's own
 * metadata rather than at HTTP responses, DNS records, or TLS certificates.
 * A host with no linked documents at all is not a failure, just zero
 * findings for that host - unlike the other fanned-out modules, an
 * unreachable homepage here only skips that one host (via HostFanOut's
 * normal per-host tolerance), it doesn't fail the whole module unless every
 * host is unreachable.
 */
@Component
public class DocumentMetadataModule implements ScanModule {

    private static final int SUBDOMAIN_CAP = 40;
    private static final int POOL_SIZE = 6;
    private static final long PER_HOST_TIMEOUT_SECONDS = 30;

    private final DocumentFetcher fetcher = new DocumentFetcher();

    @Override
    public String moduleType() {
        return "DOCUMENT_METADATA";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_1;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        HostFanOut.Result result = HostFanOut.run(
                context.hostname(),
                PayloadSubdomains.from(context),
                SUBDOMAIN_CAP,
                POOL_SIZE,
                PER_HOST_TIMEOUT_SECONDS,
                this::scanOneHost);
        return new ModuleResult(
                result.findings(),
                Map.of("hostsCovered", result.hostsCovered(), "hostsAttempted", result.hostsAttempted()));
    }

    private List<RawFinding> scanOneHost(String hostname) throws ScanModuleException {
        String homepageUrl = "https://" + hostname + "/";
        String html = fetcher.fetchHomepage(hostname);
        List<String> documentUrls = DocumentLinkDecisionLogic.extractDocumentUrls(homepageUrl, html);

        List<RawFinding> findings = new ArrayList<>();
        for (String documentUrl : documentUrls) {
            byte[] bytes = fetcher.fetchDocument(documentUrl);
            if (bytes == null) {
                continue;
            }
            DocumentMetadataParser.parse(documentUrl, bytes)
                    .ifPresent(metadata -> findings.addAll(DocumentMetadataDecisionLogic.decide(metadata)));
        }
        return findings;
    }
}
