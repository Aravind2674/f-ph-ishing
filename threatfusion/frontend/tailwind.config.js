/** @type {import('tailwindcss').Config} */

/* Colour tokens live in src/index.css as raw HSL channels; every colour here reads one of them. */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        background: "hsl(var(--bg) / <alpha-value>)",
        foreground: "hsl(var(--fg) / <alpha-value>)",
        surface: {
          DEFAULT: "hsl(var(--surface) / <alpha-value>)",
          2: "hsl(var(--surface-2) / <alpha-value>)",
          3: "hsl(var(--surface-3) / <alpha-value>)",
        },
        muted: "hsl(var(--muted) / <alpha-value>)",
        subtle: "hsl(var(--subtle) / <alpha-value>)",
        accent: "hsl(var(--accent) / <alpha-value>)",
        "accent-2": "hsl(var(--accent-2) / <alpha-value>)",
        ring: "hsl(var(--ring) / <alpha-value>)",
        ok: "hsl(var(--ok) / <alpha-value>)",
        warn: "hsl(var(--warn) / <alpha-value>)",
        danger: "hsl(var(--danger) / <alpha-value>)",
        // Hairlines carry their alpha inside the variable, so they are not alpha-value driven.
        line: "hsl(var(--line))",
        "line-strong": "hsl(var(--line-strong))",
      },
      borderColor: {
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
      keyframes: {
        shimmer: {
          "100%": { transform: "translateX(100%)" },
        },
      },
      animation: {
        shimmer: "shimmer 1.8s ease-in-out infinite",
      },
    },
  },
  plugins: [
    require("@tailwindcss/forms"),
    require("@tailwindcss/container-queries"),
  ],
};
