package org.freedonia.bloodhound.worker.modules.appstore;

/** One app-listing search result, same shape regardless of which store it came from. */
public record AppResult(
        String store, String appId, String title, String developer, String url, Double rating, Integer ratingCount) {}
