package org.freedonia.bloodhound.worker.modules.zap;

import java.util.Set;

/**
 * ZAP rules this platform deliberately doesn't run or report. A rules audit of the live
 * findings table found the top ZAP producers were informational rules that generate one row per
 * crawled URL and tell an attack-surface owner nothing actionable - and because ZAP_ALERT_* ids
 * live outside rules_catalog (see ZapAlertMapper), an admin couldn't switch them off either:
 *
 * <ul>
 *   <li>10104 User Agent Fuzzer - 980 rows, the single largest rule in the table. Not even a
 *       vulnerability check: it re-requests every URL with a dozen User-Agents and reports any
 *       response that differs. It's also the one ACTIVE rule here, so it's real extra traffic at
 *       the target for nothing.
 *   <li>10109 Modern Web Application - 517 rows. "This site uses JavaScript." Informational.
 *   <li>10015 Re-examine Cache-control Directives - 446 rows, per URL. Informational.
 *   <li>10096 Timestamp Disclosure - 317 rows. Matches any 10-digit integer in a response
 *       body; overwhelmingly false positives (asset hashes, ids, version numbers).
 *   <li>10050 Retrieved from Cache / 10112 Session Management Response Identified - ZAP
 *       bookkeeping about its own view of the traffic, not findings.
 * </ul>
 *
 * Both halves are applied: the scanners are disabled in ZAP before each run (so the fuzzer
 * never sends its traffic and the passive rules never evaluate), and {@link ZapAlertMapper}
 * drops any alert with these ids regardless, as the safety net for a ZAP instance whose state
 * didn't take the disable (a failed API call, an older container).
 */
final class ZapNoiseRules {

    static final Set<String> ACTIVE_SCANNER_IDS = Set.of("10104");
    static final Set<String> PASSIVE_SCANNER_IDS = Set.of("10015", "10050", "10096", "10109", "10112");
    static final Set<String> IGNORED_PLUGIN_IDS = Set.of("10015", "10050", "10096", "10104", "10109", "10112");

    private ZapNoiseRules() {}
}
