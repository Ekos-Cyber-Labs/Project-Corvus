import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { preferredTheme, type ThemeName } from "../lib/theme";
export type ThemeChoice = ThemeName | "system";
type ThemeContextValue = { theme: ThemeName; choice: ThemeChoice; setTheme: (c: ThemeChoice) => void; toggleTheme: () => void };
const ThemeContext = createContext<ThemeContextValue>({ theme: "dark", choice: "dark", setTheme: () => undefined, toggleTheme: () => undefined });
function resolveChoice(choice: ThemeChoice): ThemeName {
  if (choice === "dark" || choice === "light") return choice;
  try {
    if (typeof window.matchMedia !== "function") return "dark";
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  } catch {
    return "dark";
  }
}
function initialChoice(): ThemeChoice {
  try {
    const value = localStorage.getItem("corvus-theme");
    if (value === "dark" || value === "light" || value === "system") return value;
  } catch {
    return "dark";
  }
  return "dark";
}
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [choice, setChoice] = useState<ThemeChoice>(() => {
    try {
      const value = localStorage.getItem("corvus-theme");
      if (value === "dark" || value === "light" || value === "system") return value;
      return preferredTheme() === "light" ? "light" : "dark";
    } catch {
      return "dark";
    }
  });
  const [theme, setEffective] = useState<ThemeName>(() => resolveChoice(initialChoice()));
  useEffect(() => { setEffective(resolveChoice(choice)); }, [choice]);
  useEffect(() => {
    try {
      document.documentElement.dataset.theme = theme;
    } catch {
      return;
    }
  }, [theme]);
  useEffect(() => {
    if (choice !== "system") return;
    if (typeof window.matchMedia !== "function") return;
    const query = window.matchMedia("(prefers-color-scheme: light)");
    const update = () => setEffective(query.matches ? "light" : "dark");
    try {
      query.addEventListener("change", update);
      return () => query.removeEventListener("change", update);
    } catch {
      return;
    }
  }, [choice]);
  const setTheme = useCallback((next: ThemeChoice) => {
    setChoice(next);
    try {
      if (next === "system") localStorage.setItem("corvus-theme", "system");
      else localStorage.setItem("corvus-theme", next);
    } catch {
      return;
    }
  }, []);
  const toggleTheme = useCallback(() => {
    setChoice((current) => {
      const effective = current === "system" ? resolveChoice("system") : current;
      return effective === "dark" ? "light" : "dark";
    });
  }, []);
  return <ThemeContext.Provider value={{ theme, choice, setTheme, toggleTheme }}>{children}</ThemeContext.Provider>;
}
export function useTheme(): ThemeContextValue {
  return useContext(ThemeContext);
}
