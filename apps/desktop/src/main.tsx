import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { loadBackend } from "./api/backend";
import { App } from "./App";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/components.css";
import "./styles/layout.css";

// The web view never shows a context menu (no "inspect", no "copy link").
window.addEventListener("contextmenu", (e) => {
  const target = e.target as HTMLElement | null;
  if (!target?.closest("input, textarea")) e.preventDefault();
});

const root = document.getElementById("root");
if (root) {
  void loadBackend().then((backend) =>
    createRoot(root).render(
      <StrictMode>
        <App backend={backend} />
      </StrictMode>,
    ),
  );
}
