/** @type {import('tailwindcss').Config} */
// Tokens from clients/ios/design/HANDOFF.md, so the web matches the iOS design.
module.exports = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx}",
    "./components/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: { top: "#0B1020", mid: "#04050A", bottom: "#020306" },
        ink: { DEFAULT: "#F5F7FC", 2: "rgba(220,228,255,0.50)", 3: "rgba(220,228,255,0.42)" },
        signal: "#5CF2FF",
        steel: "#8A9BB8",
        ok: "#62F5A8",
        warn: "#FFB547",
        threat: "#FF5C7A",
        hairline: "rgba(255,255,255,0.08)",
        // Kept so any stray old class still resolves to the accent.
        brand: { DEFAULT: "#5CF2FF", dark: "#5CF2FF" },
      },
      fontFamily: {
        sans: ["-apple-system", "BlinkMacSystemFont", "SF Pro Text", "SF Pro Display", "system-ui", "Segoe UI", "Roboto", "Helvetica Neue", "Arial", "sans-serif"],
        mono: ["ui-monospace", "SF Mono", "SFMono-Regular", "Menlo", "Consolas", "Liberation Mono", "monospace"],
      },
      letterSpacing: { eyebrow: "0.14em" },
    },
  },
  plugins: [],
};
