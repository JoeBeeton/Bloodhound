/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Retro-Tokyo / synthwave design tokens — the shared palette every
        // later screen (dashboard, targets, compare, findings) reuses.
        void: "#0a0a12",
        panel: "#12071f",
        // A product/AppSec review found text-slate-600 (Tailwind's default #475569, 2.6:1 on
        // void) used in 21 places across the app for deliberately de-emphasized tertiary text
        // (e.g. a finding's raw display id, nested inside already-muted slate-400 text) - the
        // same WCAG AA failure severity.info below was already fixed for once, just never
        // caught here. Not simply overriding Tailwind's own slate-600: that scale backs
        // border-slate-600/bg-slate-600 too, and changing it globally would touch borders and
        // backgrounds this review never assessed. Reuses severity.low's exact tone (already a
        // proven "muted but legible" value in this palette) under a semantic name instead of
        // inventing another one-off gray.
        muted: "#7a8aa0",
        neon: {
          magenta: "#ff2e97",
          cyan: "#00f0ff",
          amber: "#ffb800",
        },
        severity: {
          critical: "#ff2e97",
          high: "#ffb800",
          medium: "#00f0ff",
          low: "#7a8aa0",
          // Was #4a5568 (2.6:1 on void - fails WCAG AA); bumped for real
          // legibility while staying visually "muted" relative to the
          // other severities, per the design-doc accessibility pass.
          info: "#94a3b8",
        },
      },
      fontFamily: {
        mono: [
          "JetBrains Mono",
          "ui-monospace",
          "SFMono-Regular",
          "Menlo",
          "Consolas",
          "monospace",
        ],
        display: ["Orbitron", "ui-sans-serif", "system-ui", "sans-serif"],
      },
      boxShadow: {
        "glow-magenta": "0 0 8px #ff2e97, 0 0 24px rgba(255,46,151,0.5)",
        "glow-cyan": "0 0 8px #00f0ff, 0 0 24px rgba(0,240,255,0.5)",
      },
    },
  },
  plugins: [],
};
