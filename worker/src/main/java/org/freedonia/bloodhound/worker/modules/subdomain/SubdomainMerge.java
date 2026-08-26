package org.freedonia.bloodhound.worker.modules.subdomain;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/**
 * Pure merge of several sources' hostname lists into one map of
 * hostname -> the set of source names that reported it. A hostname reported
 * by more than one source appears once, with both provenance tags recorded;
 * a source that returned nothing (empty list, e.g. it failed or found
 * nothing) simply contributes no entries, it doesn't fail the merge.
 */
final class SubdomainMerge {

    private SubdomainMerge() {}

    static Map<String, TreeSet<String>> merge(Map<String, List<String>> perSourceResults) {
        Map<String, TreeSet<String>> merged = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : perSourceResults.entrySet()) {
            String source = entry.getKey();
            for (String hostname : entry.getValue()) {
                merged.computeIfAbsent(hostname, h -> new TreeSet<>()).add(source);
            }
        }
        return merged;
    }
}
