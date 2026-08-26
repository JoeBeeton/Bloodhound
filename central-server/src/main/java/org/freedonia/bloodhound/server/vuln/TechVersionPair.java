package org.freedonia.bloodhound.server.vuln;

/** One distinct (technology, version) combination observed across any target's fingerprints - the cve_lookup_cache is keyed on exactly this pair, shared across all targets. */
public record TechVersionPair(String technologyName, String version) {}
