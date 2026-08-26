package org.freedonia.bloodhound.server.compound;

import java.util.List;
import org.freedonia.bloodhound.server.findings.Finding;

/** One pattern firing on one asset, with the specific findings that satisfied each required group (one per group, never the same Finding twice - see CompoundRiskEngine). */
public record CompoundMatch(CompoundPattern pattern, String affectedAsset, List<Finding> contributingFindings) {}
