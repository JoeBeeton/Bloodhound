package org.freedonia.bloodhound.worker.modules.appstore;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class AppleAppStoreClientTest {

    private final AppleAppStoreClient client = new AppleAppStoreClient();

    /** The real, live-captured shape for "example finance" - includes the genuine suspicious case this feature exists to catch (a third result published by an unrelated individual developer). */
    private static final String REAL_RESPONSE =
            """
            {"resultCount":3,"results":[
            {"trackId":1515256908,"trackName":"Example Credit Card","sellerName":"Example Finance Ltd","bundleId":"com.example.app.uk","trackViewUrl":"https://apps.apple.com/gb/app/example-credit-card/id1515256908","averageUserRating":4.81818,"userRatingCount":22},
            {"trackId":1562336144,"trackName":"ASDA Money Credit Card","sellerName":"Example Finance Ltd","bundleId":"com.example.app.uk-ASDA","trackViewUrl":"https://apps.apple.com/gb/app/asda-money/id1562336144","averageUserRating":4.94737,"userRatingCount":19},
            {"trackId":6756574462,"trackName":"EXAMPLE Finance Tracker","sellerName":"Linton Philip","bundleId":"app.lvn.EXAMPLE","trackViewUrl":"https://apps.apple.com/gb/app/example-finance-tracker/id6756574462","averageUserRating":0,"userRatingCount":0}
            ]}""";

    @Test
    void parse_realResponseShape_extractsAllFields() {
        List<AppResult> results = client.parse(REAL_RESPONSE);

        assertThat(results).hasSize(3);
        AppResult first = results.get(0);
        assertThat(first.store()).isEqualTo("APPLE_APP_STORE");
        assertThat(first.appId()).isEqualTo("1515256908");
        assertThat(first.title()).isEqualTo("Example Credit Card");
        assertThat(first.developer()).isEqualTo("Example Finance Ltd");
        assertThat(first.url()).isEqualTo("https://apps.apple.com/gb/app/example-credit-card/id1515256908");
        assertThat(first.rating()).isEqualTo(4.81818);
        assertThat(first.ratingCount()).isEqualTo(22);
    }

    @Test
    void parse_suspiciousThirdResult_hasUnrelatedDeveloper() {
        List<AppResult> results = client.parse(REAL_RESPONSE);
        AppResult suspicious = results.get(2);
        assertThat(suspicious.title()).isEqualTo("EXAMPLE Finance Tracker");
        assertThat(suspicious.developer()).isEqualTo("Linton Philip");
    }

    @Test
    void parse_emptyResults_yieldsEmptyList() {
        assertThat(client.parse("{\"resultCount\":0,\"results\":[]}")).isEmpty();
    }

    @Test
    void parse_nullInput_yieldsEmptyList() {
        assertThat(client.parse(null)).isEmpty();
    }

    @Test
    void parse_malformedJson_yieldsEmptyListRatherThanThrowing() {
        assertThat(client.parse("not json")).isEmpty();
    }

    @Test
    void parse_missingOptionalFields_toleratesNulls() {
        String json = "{\"results\":[{\"trackId\":123,\"trackName\":\"Some App\"}]}";
        List<AppResult> results = client.parse(json);
        assertThat(results).hasSize(1);
        assertThat(results.get(0).developer()).isNull();
        assertThat(results.get(0).rating()).isNull();
        assertThat(results.get(0).ratingCount()).isNull();
    }
}
