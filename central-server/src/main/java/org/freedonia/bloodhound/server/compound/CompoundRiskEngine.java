package org.freedonia.bloodhound.server.compound;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.freedonia.bloodhound.server.compound.CompoundPattern.TriggerGroup;
import org.freedonia.bloodhound.server.findings.Finding;

/**
 * Pure compound-risk pattern matching: a target's currently-OPEN primary
 * findings in, the set of dangerous co-occurrences (grouped by asset) out.
 * No DB access here - CompoundRiskAnalysisService does the fetch/persist,
 * same fetch/pure-logic/persist split used throughout this codebase (see
 * ScoringEngine, FindingReconciler).
 *
 * <p>Deliberately a small, curated set of high-confidence patterns (5, not
 * an exhaustive combinatorial sweep of every possible rule_id pairing) -
 * same "bounded catalog" discipline as the exposure-probe list and the
 * weak-cipher-suite list. A pattern fires on one asset only when every one
 * of its {@link CompoundPattern.TriggerGroup}s matches at least one
 * <i>distinct</i> finding on that asset - no single finding may satisfy two
 * groups of the same pattern, which is what makes a "any other Critical/High
 * finding" style group (pattern 2) safe to combine with a specific trigger
 * without the trigger trivially matching itself.
 */
public final class CompoundRiskEngine {

    private CompoundRiskEngine() {}

    private static Predicate<Finding> ruleIdIn(String... ruleIds) {
        Set<String> set = Set.of(ruleIds);
        return f -> set.contains(f.ruleId());
    }

    public static final List<CompoundPattern> PATTERNS = List.of(
            new CompoundPattern(
                    "COMPOUND_CREDENTIAL_TO_DATA_PIVOT",
                    "CRITICAL",
                    "Exposed credentials with a reachable path to data",
                    "This host leaks live credentials or source (an exposed .env file, AWS "
                            + "credentials, or a full .git checkout) AND separately exposes an "
                            + "unauthenticated database or admin service on the same asset. Neither "
                            + "finding alone hands over data - together they're close to a complete "
                            + "credential-to-data pivot: an attacker doesn't need to guess or crack "
                            + "anything, just read the leaked secret and connect to the open service "
                            + "right next to it.",
                    List.of(
                            new TriggerGroup(
                                    "exposed credentials or source",
                                    ruleIdIn("EXPOSURE_ENV_FILE", "EXPOSURE_AWS_CREDENTIALS", "EXPOSURE_GIT_CONFIG")),
                            new TriggerGroup(
                                    "reachable unauthenticated data/admin service",
                                    ruleIdIn(
                                            "PORT_UNEXPECTED_OPEN_ADMIN_SERVICE",
                                            "EXPOSURE_ELASTICSEARCH_UNAUTH",
                                            "EXPOSURE_REDIS_UNAUTH")))),
            new CompoundPattern(
                    "COMPOUND_CONTAINER_ESCAPE_AMPLIFICATION",
                    "CRITICAL",
                    "Exposed Docker API alongside another serious finding",
                    "An unauthenticated Docker Engine API is already close to full host "
                            + "compromise on its own (it can create, run, and mount volumes into "
                            + "containers). A second Critical or High finding on the same asset "
                            + "means whatever that finding exposes - credentials, another service, "
                            + "a misconfiguration - can very plausibly be reached or escalated from "
                            + "inside a container the Docker API lets an attacker spin up.",
                    List.of(
                            new TriggerGroup("exposed Docker API", ruleIdIn("EXPOSURE_DOCKER_API")),
                            new TriggerGroup(
                                    "another Critical/High finding",
                                    f -> !"EXPOSURE_DOCKER_API".equals(f.ruleId())
                                            && ("CRITICAL".equals(f.severity()) || "HIGH".equals(f.severity()))))),
            new CompoundPattern(
                    "COMPOUND_INTERCEPTABLE_ADMIN_ACCESS",
                    "HIGH",
                    "Admin console reachable over weak or untrusted transport",
                    "An exposed admin console (Jenkins script console, phpMyAdmin, or an "
                            + "unauthenticated Kibana) is bad enough on its own. On this asset it's "
                            + "also reachable over a connection that isn't safely encrypted - a "
                            + "self-signed/untrusted certificate, a legacy TLS protocol still "
                            + "accepted, or no HSTS - meaning credentials typed into that console are "
                            + "at real risk of interception in transit, not just abuse once reached.",
                    List.of(
                            new TriggerGroup(
                                    "exposed admin console",
                                    ruleIdIn("EXPOSURE_JENKINS_SCRIPT", "EXPOSURE_PHPMYADMIN", "EXPOSURE_KIBANA_UNAUTH")),
                            new TriggerGroup(
                                    "interceptable transport",
                                    ruleIdIn(
                                            "TLS_CERT_SELF_SIGNED_OR_UNTRUSTED_CHAIN",
                                            "TLS_WEAK_PROTOCOL_SUPPORTED",
                                            "TLS_NO_HSTS")))),
            new CompoundPattern(
                    "COMPOUND_ACTIVELY_EXPLOITED_EXPOSURE",
                    "CRITICAL",
                    "Actively-exploited software on an already-exposed host",
                    "The fingerprinted software on this asset has a CVE confirmed by CISA's "
                            + "Known Exploited Vulnerabilities catalog to be under active exploitation "
                            + "in the wild right now - not just theoretically vulnerable. Finding that "
                            + "on a host that also has a separate exposure/misconfiguration finding is "
                            + "the highest-confidence \"this will actually get hit\" signal Bloodhound "
                            + "can produce: real attackers are actively scanning for exactly this CVE.",
                    List.of(
                            new TriggerGroup(
                                    "actively-exploited CVE (CISA KEV)",
                                    ruleIdIn("TECH_KNOWN_EXPLOITED_VULNERABILITY")),
                            new TriggerGroup(
                                    "separate exposure finding on the same asset",
                                    f -> "EXPOSURE".equals(f.category())
                                            && !"TECH_KNOWN_EXPLOITED_VULNERABILITY".equals(f.ruleId())
                                            && !"TECH_KNOWN_CVE".equals(f.ruleId())))),
            new CompoundPattern(
                    "COMPOUND_SOURCE_AND_CREDENTIAL_EXPOSURE",
                    "CRITICAL",
                    "Full source checkout exposed alongside live credentials",
                    "This asset exposes both a full .git checkout (enabling reconstruction of the "
                            + "entire source repository) and a live .env file with application "
                            + "secrets. Together that's close to a complete compromise kit handed "
                            + "directly to an attacker: the application's own code to study, plus the "
                            + "credentials to run it against production.",
                    List.of(
                            new TriggerGroup("exposed .git checkout", ruleIdIn("EXPOSURE_GIT_CONFIG")),
                            new TriggerGroup("exposed .env file", ruleIdIn("EXPOSURE_ENV_FILE")))));

    /** Evaluates every pattern against every asset among {@code openFindings}, excluding any already-COMPOUND-category finding from consideration (a compound finding must never itself become another pattern's trigger). */
    public static List<CompoundMatch> evaluate(List<Finding> openFindings) {
        Map<String, List<Finding>> byAsset = openFindings.stream()
                .filter(f -> !"COMPOUND".equals(f.category()))
                .collect(Collectors.groupingBy(Finding::affectedAsset, LinkedHashMap::new, Collectors.toList()));

        List<CompoundMatch> matches = new ArrayList<>();
        for (Map.Entry<String, List<Finding>> entry : byAsset.entrySet()) {
            String asset = entry.getKey();
            List<Finding> assetFindings = entry.getValue();
            for (CompoundPattern pattern : PATTERNS) {
                matchPattern(pattern, asset, assetFindings).ifPresent(matches::add);
            }
        }
        return matches;
    }

    private static java.util.Optional<CompoundMatch> matchPattern(
            CompoundPattern pattern, String asset, List<Finding> assetFindings) {
        Set<java.util.UUID> used = new HashSet<>();
        List<Finding> contributing = new ArrayList<>();
        for (TriggerGroup group : pattern.requiredGroups()) {
            Finding match = assetFindings.stream()
                    .filter(f -> !used.contains(f.id()))
                    .filter(group.matches())
                    .findFirst()
                    .orElse(null);
            if (match == null) {
                return java.util.Optional.empty();
            }
            used.add(match.id());
            contributing.add(match);
        }
        return java.util.Optional.of(new CompoundMatch(pattern, asset, contributing));
    }
}
