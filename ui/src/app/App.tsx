import { HashRouter } from "react-router";
import { ThemeProvider } from "./providers";
import { AppShell } from "./AppShell";
import { AppRoutes } from "./routes";
import appStyles from "./App.module.css";
export function App() {
  return (
    <ThemeProvider>
      <HashRouter>
        <div className={appStyles.appRoot}>
          <AppShell>
            <AppRoutes />
          </AppShell>
        </div>
      </HashRouter>
    </ThemeProvider>
  );
}
