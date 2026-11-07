package org.freedonia.bloodhound.worker.modules.typosquat;

import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.util.Random;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Test;

class ScreenshotSimilarityTest {

    static byte[] png(BufferedImage image) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ImageIO.write(image, "png", out);
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** A homepage-like layout (header bar, hero, text blocks, buttons) driven by {@code seed}, drawn {@code shift}px off. */
    static BufferedImage page(long seed, int shift) {
        Random random = new Random(seed);
        BufferedImage image = new BufferedImage(800, 600, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, 800, 600);
        g.translate(shift, shift);
        g.setColor(new Color(random.nextInt(120), random.nextInt(120), random.nextInt(200)));
        g.fillRect(0, 0, 800, 50 + random.nextInt(40));
        g.setColor(new Color(200 + random.nextInt(55), 200, 200 + random.nextInt(55)));
        g.fillRect(40 + random.nextInt(60), 120, 300 + random.nextInt(300), 140 + random.nextInt(80));
        g.setColor(Color.DARK_GRAY);
        for (int i = 0; i < 8; i++) {
            g.fillRect(40 + random.nextInt(400), 300 + random.nextInt(260), 80 + random.nextInt(300), 10);
        }
        g.setColor(new Color(random.nextInt(255), 80, 80));
        for (int i = 0; i < 3; i++) {
            g.fillRoundRect(40 + random.nextInt(600), 280 + random.nextInt(280), 120, 40, 20, 20);
        }
        g.dispose();
        return image;
    }

    static byte[] pagePng(long seed) {
        return png(page(seed, 0));
    }

    private static BufferedImage blankWithCaption(String caption) {
        BufferedImage image = new BufferedImage(800, 600, BufferedImage.TYPE_INT_RGB);
        Graphics2D g = image.createGraphics();
        g.setColor(Color.WHITE);
        g.fillRect(0, 0, 800, 600);
        if (caption != null) {
            g.setColor(Color.BLACK);
            g.setFont(new Font("SansSerif", Font.PLAIN, 22));
            g.drawString(caption, 330, 75);
        }
        g.dispose();
        return image;
    }

    private static Integer similarity(byte[] a, byte[] b) {
        return ScreenshotSimilarity.similarityPercent(
                ScreenshotSimilarity.fingerprint(a), ScreenshotSimilarity.fingerprint(b));
    }

    @Test
    void identicalPages_100PercentSimilar() {
        assertThat(similarity(pagePng(1), pagePng(1))).isEqualTo(100);
    }

    @Test
    void cloneRenderedAFewPixelsOff_stillAboveTheCloneThreshold() {
        assertThat(similarity(pagePng(1), png(page(1, 6))))
                .isGreaterThanOrEqualTo(TyposquatDecisionLogic.CLONE_SIMILARITY_PERCENT);
    }

    @Test
    void differentLayouts_belowTheCloneThreshold() {
        for (long seed = 2; seed < 12; seed++) {
            assertThat(similarity(pagePng(1), pagePng(seed)))
                    .as("seed %d", seed)
                    .isLessThan(TyposquatDecisionLogic.CLONE_SIMILARITY_PERCENT);
        }
    }

    /**
     * Regression: the old 9x8 dHash scored a blank parked page 97% similar to a bank's homepage and
     * a "Redirecting..." stub 89% - near-uniform images all hash alike. They must get no score.
     */
    @Test
    void blankOrNearBlankPage_notInformative_noScore() {
        byte[] blank = png(blankWithCaption(null));
        byte[] redirectingStub = png(blankWithCaption("Redirecting..."));

        assertThat(ScreenshotSimilarity.fingerprint(blank).informative()).isFalse();
        assertThat(ScreenshotSimilarity.fingerprint(redirectingStub).informative()).isFalse();
        assertThat(similarity(pagePng(1), blank)).isNull();
        assertThat(similarity(blank, blank)).isNull();
        assertThat(similarity(redirectingStub, redirectingStub)).isNull();
    }

    @Test
    void realisticPage_informative() {
        assertThat(ScreenshotSimilarity.fingerprint(pagePng(1)).informative()).isTrue();
    }

    @Test
    void similarityIsSymmetric() {
        assertThat(similarity(pagePng(1), pagePng(5))).isEqualTo(similarity(pagePng(5), pagePng(1)));
    }

    @Test
    void malformedOrEmptyBytes_noFingerprint_neverThrows() {
        assertThat(ScreenshotSimilarity.fingerprint(new byte[] {1, 2, 3, 4})).isNull();
        assertThat(ScreenshotSimilarity.fingerprint(new byte[0])).isNull();
        assertThat(ScreenshotSimilarity.fingerprint(null)).isNull();
        assertThat(ScreenshotSimilarity.similarityPercent(null, ScreenshotSimilarity.fingerprint(pagePng(1)))).isNull();
    }
}
