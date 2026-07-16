/** @type {import('tailwindcss').Config} */
export default {
    content: [
      "./index.html",
      "./src/**/*.{js,ts,jsx,tsx}",
    ],
    darkMode: "class",
    theme: {
        extend: {
            "colors": {
                "outline-variant": "#424754",
                "on-secondary": "#263143",
                "surface-tint": "#adc6ff",
                "on-tertiary-fixed-variant": "#723600",
                "on-surface": "#e1e2ec",
                "secondary-fixed-dim": "#bcc7de",
                "secondary-fixed": "#d8e3fb",
                "on-tertiary-container": "#461f00",
                "tertiary": "#ffb786",
                "error-container": "#93000a",
                "outline": "#8c909f",
                "on-error": "#690005",
                "on-surface-variant": "#c2c6d6",
                "on-tertiary": "#502400",
                "surface-container-high": "#272a31",
                "on-secondary-fixed-variant": "#3c475a",
                "on-primary-fixed": "#001a42",
                "surface-bright": "#363941",
                "on-error-container": "#ffdad6",
                "tertiary-fixed": "#ffdcc6",
                "inverse-primary": "#005ac2",
                "surface-container-low": "#191b23",
                "primary-container": "#4d8eff",
                "surface-container-highest": "#32353c",
                "surface-container": "#1d2027",
                "on-secondary-fixed": "#111c2d",
                "on-primary-fixed-variant": "#004395",
                "error": "#ffb4ab",
                "tertiary-fixed-dim": "#ffb786",
                "inverse-on-surface": "#2e3038",
                "background": "#10131a",
                "surface-container-lowest": "#0b0e15",
                "on-tertiary-fixed": "#311400",
                "on-background": "#e1e2ec",
                "surface-variant": "#32353c",
                "on-secondary-container": "#aeb9d0",
                "primary-fixed-dim": "#adc6ff",
                "secondary-container": "#3e495d",
                "primary-fixed": "#d8e2ff",
                "tertiary-container": "#df7412",
                "secondary": "#bcc7de",
                "on-primary": "#002e6a",
                "primary": "#adc6ff",
                "inverse-surface": "#e1e2ec",
                "on-primary-container": "#00285d",
                "surface": "#10131a",
                "surface-dim": "#10131a"
            },
            "borderRadius": {
                "DEFAULT": "0.125rem",
                "lg": "0.25rem",
                "xl": "0.5rem",
                "full": "0.75rem"
            },
            "spacing": {
                "container-margin": "24px",
                "stack-md": "16px",
                "stack-sm": "8px",
                "gutter": "16px",
                "unit": "4px",
                "stack-lg": "32px"
            },
            "fontFamily": {
                "body-lg": ["Inter", "sans-serif"],
                "label-sm": ["Geist", "sans-serif"],
                "headline-xl": ["Outfit", "sans-serif"],
                "headline-lg": ["Outfit", "sans-serif"],
                "body-md": ["Inter", "sans-serif"],
                "mono-data": ["Geist", "monospace"],
                "headline-md": ["Outfit", "sans-serif"],
                "label-md": ["Geist", "sans-serif"],
                "body-sm": ["Inter", "sans-serif"]
            },
            "fontSize": {
                "body-lg": ["16px", { "lineHeight": "24px", "fontWeight": "400" }],
                "label-sm": ["11px", { "lineHeight": "14px", "letterSpacing": "0.08em", "fontWeight": "600" }],
                "headline-xl": ["36px", { "lineHeight": "44px", "letterSpacing": "-0.02em", "fontWeight": "700" }],
                "headline-lg": ["28px", { "lineHeight": "36px", "letterSpacing": "-0.01em", "fontWeight": "600" }],
                "body-md": ["14px", { "lineHeight": "20px", "fontWeight": "400" }],
                "mono-data": ["13px", { "lineHeight": "20px", "fontWeight": "400" }],
                "headline-md": ["20px", { "lineHeight": "28px", "fontWeight": "600" }],
                "label-md": ["13px", { "lineHeight": "16px", "letterSpacing": "0.05em", "fontWeight": "500" }],
                "body-sm": ["12px", { "lineHeight": "18px", "fontWeight": "400" }]
            }
        }
    },
    plugins: [
      require('@tailwindcss/forms'),
      require('@tailwindcss/container-queries')
    ],
  }
