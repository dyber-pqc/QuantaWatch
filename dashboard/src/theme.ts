import { createTheme, type MantineColorsTuple } from "@mantine/core";

// Microsoft / Azure "Fluent" identity: Azure blue accent, boxy 2px corners,
// flat bordered surfaces, Public Sans UI + Cascadia Code for data.
const brand: MantineColorsTuple = [
  "#eaf3fc",
  "#d3e6f9",
  "#a6ccf2",
  "#75b0eb",
  "#4f98e5",
  "#2b8ae0",
  "#0f6cbd", // Fluent 2 primary
  "#0c5aa0",
  "#094a86",
  "#063a6b",
];

const signal: MantineColorsTuple = [
  "#e6faf1",
  "#c6f2df",
  "#93e6c1",
  "#5cd9a2",
  "#33cf8b",
  "#1ac97d",
  "#0ab86e", // Fluent green
  "#009a5b",
  "#00814c",
  "#00693d",
];

// Flat neutral grays (Azure Portal dark surfaces) — index 9 = deepest.
const dark: MantineColorsTuple = [
  "#e8eaed",
  "#c5c8cd",
  "#9a9ea6",
  "#71767f",
  "#4c515a",
  "#393e46",
  "#2b2f37", // tiles/cards
  "#22262d", // panels
  "#1a1d23", // app bg
  "#12141a",
];

export const theme = createTheme({
  primaryColor: "brand",
  primaryShade: { light: 6, dark: 6 },
  colors: { brand, signal, dark },
  white: "#f3f4f6",
  black: "#12141a",
  // Boxy: crisp 2px corners everywhere.
  defaultRadius: 2,
  radius: { xs: "2px", sm: "2px", md: "3px", lg: "4px", xl: "6px" },
  fontFamily: '"Public Sans Variable", "Segoe UI", system-ui, -apple-system, sans-serif',
  fontFamilyMonospace: '"Cascadia Code", ui-monospace, "Consolas", monospace',
  headings: {
    fontFamily: '"Public Sans Variable", "Segoe UI", system-ui, sans-serif',
    fontWeight: "700",
    sizes: {
      h1: { fontSize: "1.75rem", lineHeight: "1.2" },
      h2: { fontSize: "1.3rem", lineHeight: "1.25" },
      h3: { fontSize: "1.05rem", lineHeight: "1.3" },
    },
  },
  // Flatten — Fluent tiles are bordered, not shadowed.
  shadows: { xs: "none", sm: "none", md: "none", lg: "none", xl: "none" },
  cursorType: "pointer",
  defaultGradient: { from: "brand.6", to: "brand.5", deg: 135 },
  components: {
    Paper: { defaultProps: { withBorder: true, shadow: undefined } },
    Card: { defaultProps: { withBorder: true, shadow: undefined } },
  },
});
