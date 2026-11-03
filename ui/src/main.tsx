import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./styles/fonts.css";
import { App } from "./app/App";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/utilities.css";
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
