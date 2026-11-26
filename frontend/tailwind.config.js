export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: { extend: { colors: {
    brand: { 50: "#eef6ff", 100: "#d9eaff", 500: "#2f7cf6", 600: "#1d63d8", 700: "#184fae" },
    sev: { critical: "#dc2626", high: "#ea580c", medium: "#d97706", low: "#2563eb", info: "#6b7280" } } } },
  plugins: [],
};
