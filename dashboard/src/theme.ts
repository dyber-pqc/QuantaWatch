import { createTheme, type MantineColorsTuple } from "@mantine/core";

// Distinctive violet primary (not default Mantine blue) + tuned charcoal dark
// surfaces, so the app reads as a bespoke security console, not stock Mantine.
const brand: MantineColorsTuple = [
  "#f2f0ff",
  "#e0dcff",
  "#bfb4ff",
  "#9d8bfb",
  "#8067f4",
  "#6d4ef0",
  "#5f3fe4",
  "#4d31c4",
  "#3d2aa0",
  "#2c1d78",
];

// Cool signal color for "safe / PQC" accents and positive deltas.
const signal: MantineColorsTuple = [
  "#e6fcf5",
  "#c7f5e6",
  "#95ecd0",
  "#5fe0b8",
  "#37d6a5",
  "#1fd099",
  "#0dbf8a",
  "#00a876",
  "#009167",
  "#007a56",
];

// Warm near-black charcoals with a faint violet bias (index 9 = deepest bg).
const dark: MantineColorsTuple = [
  "#e9e9f0",
  "#c6c6d2",
  "#9c9cae",
  "#74748a",
  "#52525f",
  "#3b3b47",
  "#2c2c37",
  "#1f1f27",
  "#17171d",
  "#101014",
];

export const theme = createTheme({
  primaryColor: "brand",
  primaryShade: { light: 5, dark: 5 },
  colors: { brand, signal, dark },
  white: "#f4f4f8",
  black: "#101014",
  defaultRadius: "md",
  fontFamily:
    'InterVariable, "Segoe UI", system-ui, -apple-system, sans-serif',
  fontFamilyMonospace:
    '"IBM Plex Mono", ui-monospace, "Cascadia Code", monospace',
  headings: {
    fontFamily: '"Space Grotesk Variable", "Segoe UI", system-ui, sans-serif',
    fontWeight: "650",
    sizes: {
      h1: { fontSize: "1.9rem", lineHeight: "1.15" },
      h2: { fontSize: "1.4rem", lineHeight: "1.2" },
      h3: { fontSize: "1.1rem", lineHeight: "1.25" },
    },
  },
  cursorType: "pointer",
  defaultGradient: { from: "brand.6", to: "brand.4", deg: 135 },
  components: {
    Paper: {
      defaultProps: { withBorder: true },
    },
  },
});
