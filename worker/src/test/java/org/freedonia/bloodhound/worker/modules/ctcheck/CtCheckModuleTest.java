package org.freedonia.bloodhound.worker.modules.ctcheck;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.freedonia.bloodhound.worker.modules.subdomain.CrtShSource;
import org.junit.jupiter.api.Test;

class CtCheckModuleTest {

    private final CrtShSource crtShSource = mock(CrtShSource.class);
    private final CtCheckModule module = new CtCheckModule(crtShSource);
    private final ScanContext context = new ScanContext(java.util.UUID.randomUUID(), "example.com", List.of(), java.util.Map.of());

    @Test
    void moduleTypeAndTier() {
        assertThat(module.moduleType()).isEqualTo("CT_CHECK");
        assertThat(module.tier()).isEqualTo(ScanTier.TIER_1);
    }

    @Test
    void reportsDiscoveredHostnamesViaRawMetadata() throws Exception {
        when(crtShSource.discover("example.com")).thenReturn(List.of("a.example.com", "b.example.com"));

        var result = module.execute(context);

        assertThat(result.findings()).isEmpty();
        assertThat(result.rawMetadata()).containsEntry("hostnames", List.of("a.example.com", "b.example.com"));
    }

    @Test
    void crtShFailureSurfacesAsScanModuleException() throws Exception {
        when(crtShSource.discover("example.com")).thenThrow(new java.io.IOException("crt.sh returned HTTP 502"));

        assertThatThrownBy(() -> module.execute(context))
                .isInstanceOf(ScanModuleException.class)
                .hasMessageContaining("example.com");
    }
}
