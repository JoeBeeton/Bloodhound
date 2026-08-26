package org.freedonia.bloodhound.server.notification;

/**
 * Every notification kind this app can generate. Deliberately no per-finding or
 * per-subdomain type - NEW_FINDINGS/NEW_SUBDOMAINS are always one summarized
 * notification per scan_run (see NotificationService), never one per item, because
 * a single real scan has produced 500+ new findings at once in this project's own
 * data (wikipedia.org's subfinder results) - one notification per item would flood
 * the panel unusably within the first hour of real use.
 */
public enum NotificationType {
    SCAN_STARTED,
    SCAN_COMPLETED,
    SCAN_FAILED,
    NEW_FINDINGS,
    NEW_SUBDOMAINS
}
