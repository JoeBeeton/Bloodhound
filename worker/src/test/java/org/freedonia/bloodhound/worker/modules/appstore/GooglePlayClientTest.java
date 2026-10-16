package org.freedonia.bloodhound.worker.modules.appstore;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class GooglePlayClientTest {

    private final GooglePlayClient client = new GooglePlayClient();

    /** A trimmed but structurally real fixture, built from strings captured live from a real
     * Play Store search results page for "jaja finance" (full page is ~1.2MB) - same href/title/
     * developer/rating class names and ordering confirmed against the genuine page. */
    private static String card(String appId, String title, String developer, String rating) {
        return "some preceding markup jslog=\"...\"><a class=\"Si6A0c Gy4nib\" href=\"/store/apps/details?id=" + appId
                + "\" jslog=\"38003\"><div class=\"Shbxxd\"><div class=\"yw1RKb\"><img src=\"...\" /></div></div>"
                + "<div class=\"j2FCNc\"><img src=\"...\" /></div><div class=\"cXFu1\">"
                + "<div class=\"ubGTjb\"><span class=\"DdYX5\">" + title + "</span></div>"
                + "<div class=\"ubGTjb\"><span class=\"wMUdtb\">" + developer + "</span></div>"
                + "<div class=\"ubGTjb\"><div style=\"display: inline-flex;\" role=\"img\" "
                + "aria-label=\"Rated " + rating + " stars out of five\"></div></div></div>";
    }

    @Test
    void parse_realCapturedShape_extractsTitleDeveloperRating() {
        String html = card("jaja.asda.co.uk", "ASDA Money Credit Card", "Jaja Finance", "3.9")
                + card("com.revolut.revolut", "Revolut — Banking &amp; Beyond", "Revolut Ltd", "4.7");

        List<AppResult> results = client.parse(html);

        assertThat(results).hasSize(2);
        assertThat(results.get(0).store()).isEqualTo("GOOGLE_PLAY");
        assertThat(results.get(0).appId()).isEqualTo("jaja.asda.co.uk");
        assertThat(results.get(0).title()).isEqualTo("ASDA Money Credit Card");
        assertThat(results.get(0).developer()).isEqualTo("Jaja Finance");
        assertThat(results.get(0).rating()).isEqualTo(3.9);
        assertThat(results.get(0).url()).isEqualTo("https://play.google.com/store/apps/details?id=jaja.asda.co.uk");
    }

    @Test
    void parse_htmlEntitiesInTitle_unescaped() {
        String html = card("com.revolut.revolut", "Revolut — Banking &amp; Beyond", "Revolut Ltd", "4.7");
        List<AppResult> results = client.parse(html);
        assertThat(results.get(0).title()).isEqualTo("Revolut — Banking & Beyond");
    }

    /** The "hero" top result sometimes renders without the recognized title/developer spans within the card window - skipped rather than guessed, confirmed as real live behavior in this class's own javadoc. */
    @Test
    void parse_cardMissingTitleOrDeveloperSpans_skippedRatherThanGuessed() {
        String html = "<a href=\"/store/apps/details?id=jajav2.co.uk\">no recognizable spans here, just noise padding to simulate the hero card layout</a>"
                + card("jaja.asda.co.uk", "ASDA Money Credit Card", "Jaja Finance", "3.9");

        List<AppResult> results = client.parse(html);

        assertThat(results).hasSize(1);
        assertThat(results.get(0).appId()).isEqualTo("jaja.asda.co.uk");
    }

    @Test
    void parse_noResultsAtAll_yieldsEmptyList() {
        assertThat(client.parse("<html><body>no apps found</body></html>")).isEmpty();
    }

    @Test
    void parse_nullOrBlankInput_yieldsEmptyList() {
        assertThat(client.parse(null)).isEmpty();
        assertThat(client.parse("")).isEmpty();
    }

    /** A page structure change severe enough to break the split/regex entirely must degrade to "found nothing", never throw - this module is best-effort by design (see class javadoc). */
    @Test
    void parse_whollyUnexpectedContent_doesNotThrow() {
        assertThat(client.parse("<<<not even valid markup>>> \u0000\u0001 binary garbage")).isEmpty();
    }
}
