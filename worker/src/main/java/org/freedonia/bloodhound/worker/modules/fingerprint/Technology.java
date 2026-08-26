package org.freedonia.bloodhound.worker.modules.fingerprint;

/**
 * One detected technology - mirrors central-server's Technology record, kept
 * separate since worker and central-server don't share a wire-DTO module.
 * {@code version} is null for the majority of signatures (a cookie name or a
 * CDN script path doesn't carry a version) and populated only where the
 * underlying signal actually contains one - see the version-capture cases in
 * {@link TechDecisionLogic}.
 */
public record Technology(String name, String category, String version) {

    public Technology(String name, String category) {
        this(name, category, null);
    }

    public static final String CMS = "CMS";
    public static final String FRAMEWORK = "FRAMEWORK";
    public static final String JS_LIBRARY = "JS_LIBRARY";
    public static final String CDN = "CDN";
    public static final String ANALYTICS = "ANALYTICS";
    public static final String WEB_SERVER = "WEB_SERVER";
    public static final String LANGUAGE_RUNTIME = "LANGUAGE_RUNTIME";
}
