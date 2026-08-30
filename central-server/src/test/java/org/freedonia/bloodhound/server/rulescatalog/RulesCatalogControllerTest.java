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
    private final JwtPrincipal admin = new JwtPrincipal(UUID.randomUUID(), orgId, "ADMIN", "admin@example.com");

    private RulesCatalogEntry entry(String ruleId, boolean enabled) {
        return new RulesCatalogEntry(ruleId, "DNS", "HIGH", "title", "desc", "fix it", BigDecimal.ONE, enabled);
    }

    @Test
    void setEnabled_noSuchRule_notFound_neverAudited() {
        when(jdbc.update(any(String.class), eq(false), eq("NO_SUCH_RULE"))).thenReturn(0);

        assertThatThrownBy(() -> controller.setEnabled("NO_SUCH_RULE", new RulesCatalogController.UpdateRuleEnabledRequest(false), admin))
                .isInstanceOf(ResponseStatusException.class);
        verify(auditLogRepository, never()).record(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void setEnabled_disablingARule_audited() {
        when(jdbc.update(any(String.class), eq(false), eq("DNS_SPF_MISSING"))).thenReturn(1);
        when(jdbc.queryForObject(any(String.class), any(RowMapper.class), eq("DNS_SPF_MISSING")))
                .thenReturn(entry("DNS_SPF_MISSING", false));

        RulesCatalogEntry result =
                controller.setEnabled("DNS_SPF_MISSING", new RulesCatalogController.UpdateRuleEnabledRequest(false), admin);

        assertThat(result.enabled()).isFalse();
        verify(auditLogRepository)
                .record(orgId, admin.userId(), admin.email(), "RULE_DISABLED", "RULE", "DNS_SPF_MISSING", null);
    }

    @Test
    void setEnabled_enablingARule_auditedWithEnabledAction() {
        when(jdbc.update(any(String.class), eq(true), eq("DNS_SPF_MISSING"))).thenReturn(1);
        when(jdbc.queryForObject(any(String.class), any(RowMapper.class), eq("DNS_SPF_MISSING")))
                .thenReturn(entry("DNS_SPF_MISSING", true));

        controller.setEnabled("DNS_SPF_MISSING", new RulesCatalogController.UpdateRuleEnabledRequest(true), admin);

        verify(auditLogRepository)
                .record(orgId, admin.userId(), admin.email(), "RULE_ENABLED", "RULE", "DNS_SPF_MISSING", null);
    }
}
