/** @type {import('tailwindcss').Config} */

/*
 * ThreatFusion design system — "red-team ops console".
 *
 * Strictly monochrome: there are no hues in this palette. Depth and hierarchy
 * come from layered greys, hairline borders and controlled opacity. Every colour
 * token is driven by a CSS variable (see src/index.css) expressed as raw HSL
 * channels, which lets Tailwind's `<alpha-value>` opacity modifiers work
 * (e.g. `bg-surface/50`). Severity/risk is communicated via typography weight,
 * fill-vs-outline, bar density and iconography — never hue.
 */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        background: "hsl(var(--background) / <alpha-value>)",
        foreground: "hsl(var(--foreground) / <alpha-value>)",
        surface: {
          DEFAULT: "hsl(var(--surface) / <alpha-value>)",   // elevation 1 — cards
          2: "hsl(var(--surface-2) / <alpha-value>)",         // elevation 2 — controls
          3: "hsl(var(--surface-3) / <alpha-value>)",         // elevation 3 — hover / active
        },
        muted: "hsl(var(--muted) / <alpha-value>)",           // secondary text
        subtle: "hsl(var(--subtle) / <alpha-value>)",         // tertiary text / labels
        accent: "hsl(var(--accent) / <alpha-value>)",         // near-white emphasis fill
        ring: "hsl(var(--ring) / <alpha-value>)",
        ok: "hsl(var(--ok) / <alpha-value>)",
        warn: "hsl(var(--warn) / <alpha-value>)",
        danger: "hsl(var(--danger) / <alpha-value>)",
        "accent-2": "hsl(var(--accent-2) / <alpha-value>)",
        // Hairline borders carry their alpha inside the variable itself, so they
        // are intentionally NOT alpha-value driven.
        line: "hsl(var(--line))",
        "line-strong": "hsl(var(--line-strong))",
      },
      borderColor: {
        // Default `border` utility = 1px low-opacity white hairline.
        DEFAULT: "hsl(var(--line))",
      },
      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
      },
      borderRadius: {
        sm: "calc(var(--radius) - 2px)",
        DEFAULT: "var(--radius)",
        md: "var(--radius)",
        lg: "calc(var(--radius) + 2px)",
        xl: "calc(var(--radius) + 6px)",
      },
      letterSpacing: {
        tightest: "-0.03em",
        wide2: "0.14em",
        wide3: "0.22em",
      },
      boxShadow: {
        // Subtle white "border-glow" for interactive card hover states.
        glow: "0 0 0 1px hsl(0 0% 100% / 0.14), 0 0 28px -8px hsl(0 0% 100% / 0.18)",
        "glow-sm": "0 0 0 1px hsl(0 0% 100% / 0.10), 0 0 16px -8px hsl(0 0% 100% / 0.12)",
      },
      keyframes: {
        "fade-in": {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        "fade-in-up": {
          from: { opacity: "0", transform: "translateY(12px)" },
          to: { opacity: "1", transform: "translateY(0)" },
        },
        // Vertical "scan line" sweep used by loading states instead of spinners.
        scan: {
          "0%": { transform: "translateY(-120%)", opacity: "0" },
          "10%": { opacity: "1" },
          "90%": { opacity: "1" },
          "100%": { transform: "translateY(2200%)", opacity: "0" },
        },
        // Skeleton shimmer sweep.
        shimmer: {
          "100%": { transform: "translateX(100%)" },
        },
        // Slow crosshair rotation for the idle targeting console.
        "spin-slow": {
          from: { transform: "rotate(0deg)" },
          to: { transform: "rotate(360deg)" },
        },
        // Aceternity Meteors — required by animate-meteor-effect on <Meteors />.
        "meteor-effect": {
          "0%": {
            transform: "rotate(215deg) translateX(0)",
            opacity: "1",
          },
          "70%": { opacity: "1" },
          "100%": {
            transform: "rotate(215deg) translateX(-500px)",
            opacity: "0",
          },
        },
      },
      animation: {
        "fade-in": "fade-in 0.4s ease-out both",
        "fade-in-up": "fade-in-up 0.5s cubic-bezier(0.22, 1, 0.36, 1) both",
        scan: "scan 1.8s cubic-bezier(0.4, 0, 0.2, 1) infinite",
        shimmer: "shimmer 1.8s ease-in-out infinite",
        "spin-slow": "spin-slow 24s linear infinite",
        "meteor-effect": "meteor-effect 5s linear infinite",
      },
    },
  },
  plugins: [
    require("@tailwindcss/forms"),
    require("@tailwindcss/container-queries"),
  ],
};
