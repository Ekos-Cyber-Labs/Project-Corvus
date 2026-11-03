import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { applyTheme, preferredTheme, type ThemeName } from "../lib/theme";
type ThemeContextValue = { theme: ThemeName; toggleTheme: () => void };
const ThemeContext = createContext<ThemeContextValue>({ theme: "dark", toggleTheme: () => undefined });
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<ThemeName>(() => preferredTheme());
  useEffect(() => { applyTheme(theme); }, [theme]);
  const toggleTheme = () => setTheme((current) => current === "dark" ? "light" : "dark");
  return <ThemeContext.Provider value={{ theme, toggleTheme }}>{children}</ThemeContext.Provider>;
}
export function useTheme(): ThemeContextValue {
  return useContext(ThemeContext);
}
