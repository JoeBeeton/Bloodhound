package org.freedonia.bloodhound.worker.modules.zap;

/** One alert as returned by ZAP's /JSON/core/view/alerts/ endpoint. */
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
        String evidence) {}
