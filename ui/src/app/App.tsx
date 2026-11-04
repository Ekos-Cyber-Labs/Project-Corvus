import { HashRouter } from "react-router";
import { ThemeProvider, PresentationProvider } from "./providers";
import { AppShell } from "./AppShell";
import { AppRoutes } from "./routes";
import appStyles from "./App.module.css";
export function App() {
  return (
    <ThemeProvider>
      <HashRouter>
        <PresentationProvider>
          <div className={appStyles.appRoot}>
            <AppShell>
              <AppRoutes />
            </AppShell>
          </div>
        </PresentationProvider>
      </HashRouter>
    </ThemeProvider>
  );
}
