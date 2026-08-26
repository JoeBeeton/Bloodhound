package org.freedonia.bloodhound.server.jobqueue;

/** A scan run paired with its target's hostname - what the dashboard's cross-target activity feed needs. */
public record OrgScanRun(ScanRun run, String targetHostname) {}
