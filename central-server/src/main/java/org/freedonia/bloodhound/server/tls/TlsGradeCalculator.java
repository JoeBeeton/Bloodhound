package org.freedonia.bloodhound.server.tls;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.freedonia.bloodhound.server.findings.FindingRepository.TlsFindingRow;

/**
 * Turns a hostname's open TLS-category findings into a single Qualys-SSL-Labs-style letter grade
 * (A+ through F) plus the factors that drove it - a glanceable summary for the subdomain detail
 * page, on top of the existing per-finding detail already shown in the Findings tab.
 *
 * <p>This is a deliberate, documented simplification of Qualys's own methodology, not a claim of
 * parity with it: Qualys also factors in several named-vulnerability checks this product does not
 * implement - Heartbleed, DROWN, ROBOT, Ticketbleed, insecure renegotiation, and TLS compression/
 * CRIME are all deliberately out of scope (each individually documented in TlsDecisionLogic/
 * TlsAnalysisModule's own comments: either structurally blocked by this codebase's TLS stack - no
 * SSLv2 implementation for DROWN, no compression-method visibility for CRIME - or disproportionate
 * engineering/verification risk for a vulnerability class with near-zero real-world prevalence in
 * 2026 traffic, e.g. Heartbleed needing hand-crafted raw protocol bytes this team has no way to
 * verify against a genuinely vulnerable test target). POODLE, by contrast, is implemented
 * (TLS_POODLE_VULNERABLE) since it needed no new probe at all - SSLv3's CBC-mode flaw has no fix
 * short of disabling the protocol, so the existing SSLv3-support signal already proves it. What's
 * implemented here mirrors Qualys's own published grading caps (see
 * https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide) for every check this product's
 * TLS module actually performs.
 *
 * <p><b>Known limitation: A+ is not reachable with the current rule set.</b> Every TLS-category
 * rule this calculator recognizes either caps the grade or disqualifies the A+ tier specifically
 * (see {@link #A_PLUS_DISQUALIFYING_RULES}) - there is no "everything passed" marker finding the
 * TLS module ever emits (unlike, say, nuclei's corpus size making "at least one NUCLEI_* finding
 * exists" a reliable proxy for "this host was scanned" elsewhere in this codebase - see
 * FindingRepository#findWafStatusByTarget), so a genuinely perfect host has zero open TLS findings
 * at all, indistinguishable here from "never TLS-scanned" - both read as {@link #NOT_SCANNED}.
 * Closing this would need either a dedicated "was scanned" signal (e.g. a scan_jobs lookup) or an
 * always-emitted "fully hardened" marker finding; until one exists, "A" is deliberately the
 * highest grade this calculator can ever actually produce - an honest ceiling, not a bug.
 */
public final class TlsGradeCalculator {

    private TlsGradeCalculator() {}

    /** Worst to best - index doubles as the numeric rank used throughout this class. */
    private static final List<String> GRADE_SCALE = List.of("F", "D", "C", "B", "A-", "A", "A+");
    private static final int RANK_F = 0;
    private static final int RANK_C = 2;
    private static final int RANK_B = 3;
    private static final int RANK_A_MINUS = 4;
    private static final int RANK_A = 5;
    private static final int RANK_A_PLUS = 6;

    /**
     * Rules that don't cap the grade below A (they're not current cryptographic weaknesses) but
     * still disqualify from the top A+ bar, which is meant to signal "nothing at all to act on" -
     * an HSTS gap or a cert that needs renewing soon are both exactly the kind of actionable item
     * that claim would otherwise paper over.
     */
    private static final Set<String> A_PLUS_DISQUALIFYING_RULES = Set.of(
            "TLS_NO_HSTS",
            "TLS_HSTS_SHORT_MAX_AGE",
            "TLS_HSTS_PRELOAD_NOT_ELIGIBLE",
            "TLS_HSTS_NOT_ON_PRELOAD_LIST",
            "TLS_CERT_EXPIRING_SOON");

    /** A single finding's contribution to the grade - ruleId/title straight from the finding itself, impact is this calculator's own explanation of what it capped and why. */
    public record Factor(String ruleId, String title, String impact) {}

    /** grade is null when this hostname has no open TLS findings at all - "not yet TLS-scanned", not "perfect", see SubdomainController. */
    public record Result(String grade, List<Factor> factors) {}

    public static final Result NOT_SCANNED = new Result(null, List.of());

    public static Result calculate(List<TlsFindingRow> findings) {
        if (findings == null || findings.isEmpty()) {
            return NOT_SCANNED;
        }
        int rank = RANK_A_PLUS;
        List<Factor> factors = new ArrayList<>();
        boolean disqualifiedFromAPlus = false;

        for (TlsFindingRow f : findings) {
            Integer cap = switch (f.ruleId()) {
                case "TLS_CERT_EXPIRED",
                        "TLS_CERT_SELF_SIGNED_OR_UNTRUSTED_CHAIN",
                        "TLS_CERT_HOSTNAME_MISMATCH",
                        "TLS_POODLE_VULNERABLE" -> RANK_F;
                case "TLS_WEAK_PROTOCOL_SUPPORTED" -> "SSLv3".equals(f.protocol()) ? RANK_F : RANK_B;
                case "TLS_WEAK_CIPHER_SUITE" -> weakCipherCap(f.cipherSuite());
                case "TLS_NO_FORWARD_SECRECY", "TLS_CERT_SIGNATURE_ALGORITHM_WEAK", "TLS_CT_UNEXPECTED_ISSUER" -> RANK_B;
                case "TLS_CERT_KEY_TOO_SHORT" -> RANK_C;
                case "TLS_1_3_NOT_SUPPORTED" -> RANK_A_MINUS;
                default -> null; // not grade-relevant on its own - may still gate A+, see below
            };
            if (cap != null && cap < rank) {
                rank = cap;
            }
            if (cap != null) {
                factors.add(new Factor(f.ruleId(), f.title(), "Caps grade at " + GRADE_SCALE.get(cap)));
            }
            if (A_PLUS_DISQUALIFYING_RULES.contains(f.ruleId())) {
                disqualifiedFromAPlus = true;
                if (cap == null) {
                    factors.add(new Factor(f.ruleId(), f.title(), "Keeps grade at A rather than A+"));
                }
            }
        }

        // A+ is Qualys's own highest bar, meant to signal "nothing at all to act on" - reserved for
        // when nothing capped the grade AND no lesser actionable item (a weak HSTS policy, a cert
        // that needs renewing soon) is present either. A clean-but-not-spotless host still earns a
        // plain A, not A+.
        if (rank == RANK_A_PLUS && disqualifiedFromAPlus) {
            rank = RANK_A;
        }
        return new Result(GRADE_SCALE.get(rank), factors);
    }

    /**
     * NULL/EXPORT/anonymous-DH suites offer no real protection at all (Qualys: instant F); RC4 and
     * DES/3DES are broken/deprecated but still require an active attack to exploit in practice
     * (Qualys: capped at C, not F) - see WeakCipherProbe's own javadoc for the full suite list this
     * single rule can match.
     */
    private static int weakCipherCap(String cipherSuite) {
        if (cipherSuite == null) {
            return RANK_C;
        }
        String upper = cipherSuite.toUpperCase(Locale.ROOT);
        if (upper.contains("NULL") || upper.contains("EXPORT") || upper.contains("ANON")) {
            return RANK_F;
        }
        return RANK_C;
    }
}
