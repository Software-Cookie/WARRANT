import type { Config } from "tailwindcss";

// Every colour comes from a CSS token in app/globals.css. No hard-coded colour in any component.
const token = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  darkMode: "media",
  theme: {
    colors: {
      transparent: "transparent",
      bg: token("bg"),
      surface: token("surface"),
      sunken: token("sunken"),
      line: token("line"),
      ink: token("ink"),
      muted: token("muted"),
      faint: token("faint"),
      accent: token("accent"),
      "on-accent": token("on-accent"),
      danger: token("danger"),
      caution: token("caution"),
      safe: token("safe"),
      "on-signal": token("on-signal"),
    },
    fontFamily: {
      sans: ["var(--font-sans)"],
      mono: ["var(--font-mono)"],
    },
    extend: {
      borderRadius: { card: "10px" },
    },
  },
} satisfies Config;
