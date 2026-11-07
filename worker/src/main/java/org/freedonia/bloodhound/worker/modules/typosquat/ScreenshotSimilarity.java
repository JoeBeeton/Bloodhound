package org.freedonia.bloodhound.worker.modules.typosquat;

import java.awt.Image;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import javax.imageio.ImageIO;

/**
 * Compares where two screenshots have edges (direction of brightness steps on a 32x32 grid, with
 * one-cell tolerance), ignoring flat areas. A plain 64-bit dHash scored blank/parked pages ~90%
 * similar to real homepages, since near-uniform images all hash alike. Calibrated on prod
 * screenshots: unrelated pages scored at most 55, shifted/rescaled/partly-covered copies 72+.
 */
public final class ScreenshotSimilarity {

    static final int GRID = 32;
    /** Grayscale step (0-255, after area-averaging) that counts as an edge rather than noise. */
    static final int EDGE_THRESHOLD = 6;
    /** Below this share of edge cells a screenshot is effectively blank - nothing to compare. */
    static final double MIN_DETAIL = 0.04;

    private ScreenshotSimilarity() {}

    /** Edge directions per cell: index [0] horizontal steps, [1] vertical steps, each GRID x GRID. */
    public record Fingerprint(byte[][][] edges, double detail) {
        public boolean informative() {
            return detail >= MIN_DETAIL;
        }
    }

    /** Null if the bytes aren't a decodable image - never throws, screenshotting is best-effort. */
    public static Fingerprint fingerprint(byte[] pngBytes) {
        if (pngBytes == null || pngBytes.length == 0) {
            return null;
        }
        try {
            BufferedImage original = ImageIO.read(new ByteArrayInputStream(pngBytes));
            if (original == null) {
                return null;
            }
            int[][] gray = shrinkToGrayscale(original);
            byte[][][] edges = new byte[2][GRID][GRID];
            int edgeCells = 0;
            for (int y = 0; y < GRID; y++) {
                for (int x = 0; x < GRID; x++) {
                    if (x < GRID - 1) {
                        edges[0][y][x] = direction(gray[y][x] - gray[y][x + 1]);
                        edgeCells += edges[0][y][x] != 0 ? 1 : 0;
                    }
                    if (y < GRID - 1) {
                        edges[1][y][x] = direction(gray[y][x] - gray[y + 1][x]);
                        edgeCells += edges[1][y][x] != 0 ? 1 : 0;
                    }
                }
            }
            return new Fingerprint(edges, edgeCells / (2.0 * GRID * (GRID - 1)));
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /** 0-100, or null when either side is missing or effectively blank. */
    public static Integer similarityPercent(Fingerprint a, Fingerprint b) {
        if (a == null || b == null || !a.informative() || !b.informative()) {
            return null;
        }
        return (int) Math.round(100 * Math.min(matchedShare(a, b), matchedShare(b, a)));
    }

    private static double matchedShare(Fingerprint from, Fingerprint in) {
        int edges = 0;
        int matched = 0;
        for (int k = 0; k < 2; k++) {
            for (int y = 0; y < GRID; y++) {
                for (int x = 0; x < GRID; x++) {
                    byte edge = from.edges()[k][y][x];
                    if (edge == 0) {
                        continue;
                    }
                    edges++;
                    if (hasNearby(in.edges()[k], y, x, edge)) {
                        matched++;
                    }
                }
            }
        }
        return edges == 0 ? 0 : (double) matched / edges;
    }

    private static boolean hasNearby(byte[][] edges, int y, int x, byte edge) {
        for (int dy = -1; dy <= 1; dy++) {
            for (int dx = -1; dx <= 1; dx++) {
                int yy = y + dy;
                int xx = x + dx;
                if (yy >= 0 && xx >= 0 && yy < GRID && xx < GRID && edges[yy][xx] == edge) {
                    return true;
                }
            }
        }
        return false;
    }

    private static byte direction(int step) {
        return (byte) (step > EDGE_THRESHOLD ? 1 : step < -EDGE_THRESHOLD ? -1 : 0);
    }

    private static int[][] shrinkToGrayscale(BufferedImage original) {
        Image scaled = original.getScaledInstance(GRID, GRID, Image.SCALE_AREA_AVERAGING);
        BufferedImage small = new BufferedImage(GRID, GRID, BufferedImage.TYPE_BYTE_GRAY);
        var graphics = small.getGraphics();
        try {
            graphics.drawImage(scaled, 0, 0, null);
        } finally {
            graphics.dispose();
        }
        int[][] gray = new int[GRID][GRID];
        for (int y = 0; y < GRID; y++) {
            for (int x = 0; x < GRID; x++) {
                gray[y][x] = small.getRGB(x, y) & 0xFF;
            }
        }
        return gray;
    }
}
