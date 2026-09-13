package org.freedonia.bloodhound.server.rulescatalog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigDecimal;
import java.util.UUID;
import org.freedonia.bloodhound.server.audit.AuditLogRepository;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.server.ResponseStatusException;

class RulesCatalogControllerTest {

    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
    private final RulesCatalogController controller = new RulesCatalogController(jdbc, auditLogRepository);

    private final UUID orgId = UUID.randomUUID();
    private final UUID otherOrgId = UUID.randomUUID();
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");

    private RulesCatalogEntry entry(String ruleId, boolean enabled) {
        return new RulesCatalogEntry(ruleId, "DNS", "HIGH", "title", "desc", "fix it", BigDecimal.ONE, enabled);
    }

    @Test
    void setEnabled_differentOrg_notFound_neverWrites() {
        assertThatThrownBy(() -> controller.setEnabled(
                        otherOrgId, "DNS_SPF_MISSING", new RulesCatalogController.UpdateRuleEnabledRequest(false), admin))
                .isInstanceOf(ResponseStatusException.class);
        verify(jdbc, never())
                .update(org.mockito.ArgumentMatchers.contains("org_rule_overrides"), any(), any(), any(Boolean.class));
    }

    @Test
    void setEnabled_noSuchRule_notFound_neverAudited() {
        when(jdbc.queryForObject(any(String.class), eq(Integer.class), eq("NO_SUCH_RULE"))).thenReturn(0);

        assertThatThrownBy(() -> controller.setEnabled(
                        orgId, "NO_SUCH_RULE", new RulesCatalogController.UpdateRuleEnabledRequest(false), admin))
                .isInstanceOf(ResponseStatusException.class);
        verify(auditLogRepository, never()).record(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void setEnabled_disablingARule_writesAnOrgScopedOverride_notTheGlobalCatalogRow_audited() {
        when(jdbc.queryForObject(any(String.class), eq(Integer.class), eq("DNS_SPF_MISSING"))).thenReturn(1);
        when(jdbc.queryForObject(any(String.class), any(RowMapper.class), eq(orgId), eq("DNS_SPF_MISSING")))
                .thenReturn(entry("DNS_SPF_MISSING", false));

        RulesCatalogEntry result = controller.setEnabled(
                orgId, "DNS_SPF_MISSING", new RulesCatalogController.UpdateRuleEnabledRequest(false), admin);

        assertThat(result.enabled()).isFalse();
        // The write targets org_rule_overrides (a per-org overlay), never a bare UPDATE against
        // rules_catalog itself - that global-write shape is exactly the cross-tenant gap this
        // fixes (see the class javadoc).
        verify(jdbc)
                .update(
                        org.mockito.ArgumentMatchers.contains("INSERT INTO org_rule_overrides"),
                        eq(orgId),
                        eq("DNS_SPF_MISSING"),
                        eq(false));
        verify(jdbc, never()).update(org.mockito.ArgumentMatchers.contains("UPDATE rules_catalog"), any(), any());
        verify(auditLogRepository)
                .record(orgId, admin.userId(), admin.email(), "RULE_DISABLED", "RULE", "DNS_SPF_MISSING", null);
    }

    @Test
    void setEnabled_enablingARule_auditedWithEnabledAction() {
        when(jdbc.queryForObject(any(String.class), eq(Integer.class), eq("DNS_SPF_MISSING"))).thenReturn(1);
        when(jdbc.queryForObject(any(String.class), any(RowMapper.class), eq(orgId), eq("DNS_SPF_MISSING")))
                .thenReturn(entry("DNS_SPF_MISSING", true));

        controller.setEnabled(orgId, "DNS_SPF_MISSING", new RulesCatalogController.UpdateRuleEnabledRequest(true), admin);

        verify(auditLogRepository)
                .record(orgId, admin.userId(), admin.email(), "RULE_ENABLED", "RULE", "DNS_SPF_MISSING", null);
    }

    /**
     * ZAP_ALERT_* / NUCLEI_* ids have no catalog row (V55 dropped the FK that made that fatal):
     * the disable must still write the org-scoped override and be audited, so an admin can switch
     * off e.g. ZAP's User Agent Fuzzer - the largest rule in the findings table with no switch.
     */
    @Test
    void setEnabled_passThroughRuleNotInCatalog_stillWritesOverrideAndAudits() {
        when(jdbc.queryForObject(any(String.class), eq(Integer.class), eq("ZAP_ALERT_10104"))).thenReturn(0);
        when(jdbc.query(any(String.class), any(RowMapper.class), eq(orgId), eq(orgId), eq(orgId)))
                .thenReturn(java.util.List.of(entry("ZAP_ALERT_10104", false)));

        RulesCatalogEntry result = controller.setEnabled(
                orgId, "ZAP_ALERT_10104", new RulesCatalogController.UpdateRuleEnabledRequest(false), admin);

        assertThat(result.ruleId()).isEqualTo("ZAP_ALERT_10104");
        assertThat(result.enabled()).isFalse();
        verify(jdbc)
                .update(
                        org.mockito.ArgumentMatchers.contains("INSERT INTO org_rule_overrides"),
                        eq(orgId),
                        eq("ZAP_ALERT_10104"),
                        eq(false));
        verify(auditLogRepository)
                .record(orgId, admin.userId(), admin.email(), "RULE_DISABLED", "RULE", "ZAP_ALERT_10104", null);
    }

    @Test
    void passThroughRuleIdShape_isOnlyTheTwoScannerPrefixes() {
        assertThat(RulesCatalogController.isPassThroughRuleId("ZAP_ALERT_10104")).isTrue();
        assertThat(RulesCatalogController.isPassThroughRuleId("NUCLEI_deprecated-tls")).isTrue();
        assertThat(RulesCatalogController.isPassThroughRuleId("DNS_SPF_MISSING")).isFalse();
        assertThat(RulesCatalogController.isPassThroughRuleId("ANYTHING_ELSE")).isFalse();
        assertThat(RulesCatalogController.isPassThroughRuleId(null)).isFalse();
    }
}
