package org.freedonia.bloodhound.server.fingerprint;

/**
 * One detected technology, as reported by the worker's TECH_FINGERPRINT
 * module. {@code version} is null for the majority of signatures - only a
 * handful (nginx/Apache/PHP/WordPress today) carry a version in the raw
 * signal the worker's signature catalog matches against.
 */
public record Technology(String name, String category, String version) {}
