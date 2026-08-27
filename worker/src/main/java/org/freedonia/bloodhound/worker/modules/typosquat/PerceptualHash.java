package org.freedonia.bloodhound.worker.modules.typosquat;

import java.awt.Image;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import javax.imageio.ImageIO;

/**
 * Perceptual image hashing for the "does this lookalike domain's homepage
 * actually look like the real one" check - a difference hash (dHash), not a
 * true DCT-based pHash: dHash is simpler to implement correctly with nothing
 * but the JDK's own {@code java.awt}/{@code javax.imageio} (no third-party
 * image-hashing library, so no new dependency/license to track), and is
 * plenty robust for comparing two full-page screenshots against each other -
 * DCT-based pHash's extra robustness mostly matters for photographic content
 * and format/compression-artifact resilience, not this use case.
 *
 * <p>Algorithm: shrink to 9x8 grayscale, then for each of the 8 rows compare
 * each of the 9 pixels against its right-hand neighbor (8 comparisons per
 * row = 64 bits total, packed into a {@code long}). Two hashes' Hamming
 * distance (bits differing) is a similarity measure - identical layout/
 * gradient structure gives a small distance regardless of exact colors used,
 * which is exactly what matters for "did someone clone this page's look."
 */
public final class PerceptualHash {

    private static final int HASH_WIDTH = 9;
    private static final int HASH_HEIGHT = 8;
    static final int HASH_BITS = (HASH_WIDTH - 1) * HASH_HEIGHT;

    private PerceptualHash() {}

    /** Returns null if the bytes aren't a decodable image - never throws, screenshotting/hashing is best-effort. */
    public static Long hash(byte[] pngBytes) {
        if (pngBytes == null || pngBytes.length == 0) {
            return null;
        }
        try {
            BufferedImage original = ImageIO.read(new ByteArrayInputStream(pngBytes));
            if (original == null) {
                return null;
            }
            BufferedImage small = shrinkToGrayscale(original);
            long hash = 0L;
            int bit = 0;
            for (int y = 0; y < HASH_HEIGHT; y++) {
                for (int x = 0; x < HASH_WIDTH - 1; x++) {
                    int left = small.getRGB(x, y) & 0xFF;
                    int right = small.getRGB(x + 1, y) & 0xFF;
                    if (left > right) {
                        hash |= 1L << bit;
                    }
                    bit++;
                }
            }
            return hash;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /**
     * 0-100: 100 means identical hashes (distance 0), 0 means maximally
     * different (all 64 bits differ - never actually reached in practice for
     * two real webpage screenshots, but mathematically the floor).
     */
    public static int similarityPercent(long hashA, long hashB) {
        int distance = Long.bitCount(hashA ^ hashB);
        return Math.round(100f * (HASH_BITS - distance) / HASH_BITS);
    }

    private static BufferedImage shrinkToGrayscale(BufferedImage original) {
        Image scaled = original.getScaledInstance(HASH_WIDTH, HASH_HEIGHT, Image.SCALE_AREA_AVERAGING);
        BufferedImage gray = new BufferedImage(HASH_WIDTH, HASH_HEIGHT, BufferedImage.TYPE_BYTE_GRAY);
        var graphics = gray.getGraphics();
        try {
            graphics.drawImage(scaled, 0, 0, null);
        } finally {
            graphics.dispose();
        }
        return gray;
    }
}
