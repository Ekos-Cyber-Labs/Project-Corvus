export type ThemeName = "dark" | "light";
export const THEME_STORAGE_KEY = "corvus-theme";
export function storedTheme(): ThemeName | null {
  try {
    const value = localStorage.getItem(THEME_STORAGE_KEY);
    return value === "dark" || value === "light" ? value : null;
  } catch {
    return null;
  }
}
export function preferredTheme(): ThemeName {
  const stored = storedTheme();
  if (stored) return stored;
  return "dark";
}
export function applyTheme(theme: ThemeName): void {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    return;
  }
}
