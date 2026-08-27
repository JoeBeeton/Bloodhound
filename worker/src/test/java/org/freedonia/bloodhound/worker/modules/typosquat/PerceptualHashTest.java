package org.freedonia.bloodhound.worker.modules.typosquat;

import static org.assertj.core.api.Assertions.assertThat;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Test;

class PerceptualHashTest {

    private static byte[] png(BufferedImage image) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ImageIO.write(image, "png", out);
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** A vertical gradient (dark left, light right per row-band) - gives dHash's row-wise left/right comparisons real structure to detect, unlike a flat color. */
    private static BufferedImage gradient(int width, int height) {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        var g = image.getGraphics();
        for (int band = 0; band < 8; band++) {
            int bandHeight = height / 8;
            int gray = band * 32;
            g.setColor(new Color(gray, gray, gray));
            g.fillRect(0, band * bandHeight, width / 2, bandHeight);
            g.setColor(new Color(255 - gray, 255 - gray, 255 - gray));
            g.fillRect(width / 2, band * bandHeight, width - width / 2, bandHeight);
        }
        g.dispose();
        return image;
    }

    private static BufferedImage flatColor(int width, int height, Color color) {
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        var g = image.getGraphics();
        g.setColor(color);
        g.fillRect(0, 0, width, height);
        g.dispose();
        return image;
    }

    @Test
    void identicalImages_100PercentSimilar() {
        byte[] image = png(gradient(400, 300));
        Long hashA = PerceptualHash.hash(image);
        Long hashB = PerceptualHash.hash(image);

        assertThat(hashA).isNotNull();
        assertThat(PerceptualHash.similarityPercent(hashA, hashB)).isEqualTo(100);
    }

    @Test
    void sameStructureDifferentExactColors_stillHighlySimilar() {
        // Same light/dark left-right structure per band, but shifted color values - dHash
        // compares relative brightness (left > right), not exact pixel values, so this
        // should still score very highly even though no pixel matches exactly.
        BufferedImage a = new BufferedImage(400, 300, BufferedImage.TYPE_INT_RGB);
        BufferedImage b = new BufferedImage(400, 300, BufferedImage.TYPE_INT_RGB);
        var ga = a.getGraphics();
        var gb = b.getGraphics();
        for (int band = 0; band < 8; band++) {
            int bandHeight = 300 / 8;
            ga.setColor(new Color(20, 20, 20));
            ga.fillRect(0, band * bandHeight, 200, bandHeight);
            ga.setColor(new Color(230, 230, 230));
            ga.fillRect(200, band * bandHeight, 200, bandHeight);
            gb.setColor(new Color(60, 60, 60));
            gb.fillRect(0, band * bandHeight, 200, bandHeight);
            gb.setColor(new Color(190, 190, 190));
            gb.fillRect(200, band * bandHeight, 200, bandHeight);
        }
        ga.dispose();
        gb.dispose();

        Long hashA = PerceptualHash.hash(png(a));
        Long hashB = PerceptualHash.hash(png(b));

        assertThat(PerceptualHash.similarityPercent(hashA, hashB)).isEqualTo(100);
    }

    /**
     * A checkerboard has genuinely different left/right-neighbor gradient structure in
     * nearly every one of dHash's 64 row comparisons than a plain two-band gradient - unlike
     * simply inverting a mostly-flat image's colors (which barely changes dHash's bits at
     * all, since dHash encodes gradients between adjacent pixels, not absolute brightness -
     * a flat region stays "flat" under inversion either way).
     */
    @Test
    void structurallyDifferentImages_lowSimilarity() {
        BufferedImage checkerboard = new BufferedImage(400, 300, BufferedImage.TYPE_INT_RGB);
        var g = checkerboard.getGraphics();
        int cols = 9;
        int rows = 8;
        for (int row = 0; row < rows; row++) {
            for (int col = 0; col < cols; col++) {
                g.setColor((row + col) % 2 == 0 ? Color.BLACK : Color.WHITE);
                g.fillRect(col * 400 / cols, row * 300 / rows, 400 / cols + 1, 300 / rows + 1);
            }
        }
        g.dispose();

        Long hashA = PerceptualHash.hash(png(gradient(400, 300)));
        Long hashB = PerceptualHash.hash(png(checkerboard));

        assertThat(PerceptualHash.similarityPercent(hashA, hashB)).isLessThan(60);
    }

    @Test
    void malformedImageBytes_returnsNull_neverThrows() {
        assertThat(PerceptualHash.hash(new byte[] {1, 2, 3, 4})).isNull();
    }

    @Test
    void emptyOrNullBytes_returnsNull() {
        assertThat(PerceptualHash.hash(new byte[0])).isNull();
        assertThat(PerceptualHash.hash(null)).isNull();
    }

    @Test
    void similarityIsSymmetric() {
        byte[] imageA = png(flatColor(100, 100, Color.RED));
        byte[] imageB = png(gradient(100, 100));
        long hashA = PerceptualHash.hash(imageA);
        long hashB = PerceptualHash.hash(imageB);

        assertThat(PerceptualHash.similarityPercent(hashA, hashB))
                .isEqualTo(PerceptualHash.similarityPercent(hashB, hashA));
    }
}
