// Modal dialog: focus moves inside, Tab stays inside, Escape closes, focus
// returns to the element that opened it.

import { useEffect, useId, useRef, type ReactNode } from "react";
import { Icon, type IconName } from "./Icon";

const FOCUSABLE =
  'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function Dialog({
  title,
  icon = "info",
  danger = false,
  onClose,
  children,
  actions,
}: {
  title: string;
  icon?: IconName;
  danger?: boolean;
  onClose: () => void;
  children: ReactNode;
  actions: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const node = ref.current;
    const first = node?.querySelector<HTMLElement>("input, textarea, select") ??
      node?.querySelector<HTMLElement>(FOCUSABLE);
    first?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
        onClose();
      } else if (e.key === "Tab" && node) {
        const items = Array.from(node.querySelectorAll<HTMLElement>(FOCUSABLE));
        const firstItem = items[0];
        const lastItem = items[items.length - 1];
        if (!firstItem || !lastItem) return;
        if (e.shiftKey && document.activeElement === firstItem) {
          e.preventDefault();
          lastItem.focus();
        } else if (!e.shiftKey && document.activeElement === lastItem) {
          e.preventDefault();
          firstItem.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey, true);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      previous?.focus();
    };
  }, [onClose]);

  return (
    <div
      className="dialog-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId} ref={ref}>
        <div className="dialog-header">
          <div className={`dialog-icon ${danger ? "danger" : ""}`}>
            <Icon name={icon} />
          </div>
          <h3 id={titleId}>{title}</h3>
        </div>
        {children}
        <div className="dialog-actions">{actions}</div>
      </div>
    </div>
  );
}
