package org.freedonia.bloodhound.worker.modules.zap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;

class ZapAlertParserTest {

    @Test
    void parsesAllFieldsFromARealisticAlertsResponse() {
        String json =
                """
                {
                  "alerts": [
                    {
                      "pluginId": "10038",
                      "alert": "Content Security Policy (CSP) Header Not Set",
                      "name": "Content Security Policy (CSP) Header Not Set",
                      "risk": "Medium",
                      "confidence": "High",
                      "description": "CSP is an HTTP header that allows site operators fine-grained control...",
                      "solution": "Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.",
                      "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
                      "url": "http://juiceshop.local/",
                      "param": "",
                      "evidence": ""
                    }
                  ]
                }
                """;

        List<ZapAlert> alerts = ZapAlertParser.parse(json);

        assertThat(alerts).hasSize(1);
        ZapAlert alert = alerts.get(0);
        assertThat(alert.pluginId()).isEqualTo("10038");
        assertThat(alert.name()).isEqualTo("Content Security Policy (CSP) Header Not Set");
        assertThat(alert.risk()).isEqualTo("Medium");
        assertThat(alert.confidence()).isEqualTo("High");
        assertThat(alert.url()).isEqualTo("http://juiceshop.local/");
        assertThat(alert.solution()).contains("Content-Security-Policy header");
        assertThat(alert.reference()).contains("developer.mozilla.org");
    }

    @Test
    void fallsBackToAlertFieldWhenNameIsAbsent() {
        // Some ZAP API versions/views only return "alert", not "name" - the
        // parser must not silently drop the title in that case.
        String json =
                """
                {"alerts": [{"pluginId": "40012", "alert": "Cross Site Scripting (Reflected)", "risk": "High"}]}
                """;

        List<ZapAlert> alerts = ZapAlertParser.parse(json);

        assertThat(alerts).hasSize(1);
        assertThat(alerts.get(0).name()).isEqualTo("Cross Site Scripting (Reflected)");
    }

    @Test
    void parsesOtherField_whereZapPutsPerFindingLibraryAndCveDetail() {
        String json =
                """
                {
                  "alerts": [
                    {
                      "pluginId": "10003",
                      "name": "Vulnerable JS Library",
                      "risk": "High",
                      "other": "CVE-2024-21490: Angular, version 17.1.0, is vulnerable. Upgrade to 17.3.0 or later."
                    }
                  ]
                }
                """;

        List<ZapAlert> alerts = ZapAlertParser.parse(json);

        assertThat(alerts.get(0).other()).contains("CVE-2024-21490").contains("17.3.0");
    }

    @Test
    void handlesMultipleAlertsAndMissingOptionalFields() {
        String json =
                """
                {
                  "alerts": [
                    {"pluginId": "10038", "name": "CSP Header Not Set", "risk": "Medium"},
                    {"pluginId": "10096", "name": "Timestamp Disclosure", "risk": "Low", "param": "X-Timestamp"},
                    {"pluginId": "2", "name": "Private IP Disclosure", "risk": "Informational"}
                  ]
                }
                """;

        List<ZapAlert> alerts = ZapAlertParser.parse(json);

        assertThat(alerts).hasSize(3);
        assertThat(alerts).extracting(ZapAlert::pluginId).containsExactly("10038", "10096", "2");
        assertThat(alerts.get(1).param()).isEqualTo("X-Timestamp");
        assertThat(alerts.get(0).param()).isNull();
    }

    @Test
    void emptyAlertsArrayProducesEmptyList() {
        assertThat(ZapAlertParser.parse("{\"alerts\": []}")).isEmpty();
    }

    @Test
    void malformedJsonThrows() {
        assertThatThrownBy(() -> ZapAlertParser.parse("not json at all"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
