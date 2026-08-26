package org.freedonia.bloodhound.worker.modules.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class HostingProviderMapperTest {

    @Test
    void recognizesAmazon() {
        assertThat(HostingProviderMapper.toFriendlyName("AMAZON-02, US")).isEqualTo("Amazon Web Services");
    }

    @Test
    void recognizesHetzner() {
        assertThat(HostingProviderMapper.toFriendlyName("HETZNER-AS, DE")).isEqualTo("Hetzner Online GmbH");
    }

    @Test
    void recognizesCloudflareNet() {
        assertThat(HostingProviderMapper.toFriendlyName("CLOUDFLARENET, US")).isEqualTo("Cloudflare");
    }

    @Test
    void recognizesDigitalOcean() {
        assertThat(HostingProviderMapper.toFriendlyName("DIGITALOCEAN-ASN, US")).isEqualTo("DigitalOcean");
    }

    @Test
    void unrecognizedProvider_fallsBackToRawString() {
        assertThat(HostingProviderMapper.toFriendlyName("SOME-SMALL-ISP-LTD, XX")).isEqualTo("SOME-SMALL-ISP-LTD, XX");
    }

    @Test
    void nullOrBlank_returnsNull() {
        assertThat(HostingProviderMapper.toFriendlyName(null)).isNull();
        assertThat(HostingProviderMapper.toFriendlyName("")).isNull();
    }
}
