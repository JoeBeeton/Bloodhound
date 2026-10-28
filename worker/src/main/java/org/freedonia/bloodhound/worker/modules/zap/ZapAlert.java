package org.freedonia.bloodhound.worker.modules.zap;

/**
 * One alert as returned by ZAP's /JSON/core/view/alerts/ endpoint.
 *
 * @param other ZAP's free-text "supplementary info" field - blank/absent for most rules, but the
 *     one place several rules (notably plugin 10003, "Vulnerable JS Library", backed by the
 *     retire.js add-on) put the actual per-finding specifics: which library, which version was
 *     detected, and which CVE(s)/advisory it matches - unlike description/solution, which are a
 *     single static blurb shared by every instance of that plugin regardless of what it actually
 *     found. See ZapAlertMapper#map for where this gets folded into the finding.
 */
public record ZapAlert(
        String pluginId,
        String name,
        String risk,
        String confidence,
        String description,
        String solution,
        String reference,
        String url,
        String param,
        String evidence,
        String other) {}
