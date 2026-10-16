package org.freedonia.bloodhound.worker.modules.appstore;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AppStoreMonitorModuleTest {

    @Test
    void brandTerm_usesFirstLabelOnly() {
        assertThat(AppStoreMonitorModule.brandTerm("jaja.co.uk")).isEqualTo("jaja");
        assertThat(AppStoreMonitorModule.brandTerm("monzo.com")).isEqualTo("monzo");
        assertThat(AppStoreMonitorModule.brandTerm("118118money.com")).isEqualTo("118118money");
    }

    @Test
    void brandTerm_lowercased() {
        assertThat(AppStoreMonitorModule.brandTerm("JAJA.CO.UK")).isEqualTo("jaja");
    }

    @Test
    void brandTerm_tooShort_returnsNull() {
        assertThat(AppStoreMonitorModule.brandTerm("ab.com")).isNull();
    }

    @Test
    void brandTerm_exactlyMinLength_returned() {
        assertThat(AppStoreMonitorModule.brandTerm("abc.com")).isEqualTo("abc");
    }
}
