import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { browserApi } from "./api";
import { Popup } from "./Popup";
import "./popup.css";

const root = document.getElementById("root");
if (root) {
  document.documentElement.lang = browserApi.language().toLowerCase().startsWith("fr") ? "fr" : "en";
  createRoot(root).render(
    <StrictMode>
      <Popup api={browserApi} />
    </StrictMode>,
  );
}
