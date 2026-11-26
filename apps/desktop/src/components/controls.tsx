// Form controls and small building blocks.

import {
  useId,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from "react";
import { useI18n } from "../i18n";
import type { StrengthLevel } from "../api/types";
import { Icon, type IconName } from "./Icon";

type Variant = "primary" | "secondary" | "ghost" | "danger" | "danger-ghost";

export function Button({
  variant = "secondary",
  size,
  icon,
  busy = false,
  block = false,
  children,
  className = "",
  disabled,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  size?: "sm" | "lg";
  icon?: IconName;
  busy?: boolean;
  block?: boolean;
}) {
  const classes = [
    "btn",
    `btn-${variant}`,
    size ? `btn-${size}` : "",
    block ? "btn-block" : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <button
      type="button"
      className={classes}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      {...rest}
    >
      {busy ? <span className="spinner" /> : icon ? <Icon name={icon} /> : null}
      {children}
    </button>
  );
}

export function IconButton({
  icon,
  label,
  active = false,
  filled = false,
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  icon: IconName;
  label: string;
  active?: boolean;
  filled?: boolean;
}) {
  return (
    <button
      type="button"
      className={`icon-btn ${active ? "active" : ""} ${className}`}
      aria-label={label}
      title={label}
      {...rest}
    >
      <Icon name={icon} filled={filled} />
    </button>
  );
}

export function Field({
  label,
  hint,
  error,
  htmlFor,
  hideLabel = false,
  children,
}: {
  label: string;
  hint?: string | undefined;
  error?: string | null | undefined;
  htmlFor: string;
  /** Keep the label for assistive technologies only (it is shown nearby). */
  hideLabel?: boolean;
  children: ReactNode;
}) {
  return (
    <div className="field">
      <label className={hideLabel ? "visually-hidden" : "field-label"} htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {error ? (
        <span className="field-error" role="alert">
          {error}
        </span>
      ) : hint ? (
        <span className="field-hint">{hint}</span>
      ) : null}
    </div>
  );
}

export function TextField({
  label,
  hint,
  error,
  icon,
  large = false,
  actions,
  ...input
}: InputHTMLAttributes<HTMLInputElement> & {
  label: string;
  hint?: string;
  error?: string | null;
  icon?: IconName;
  large?: boolean;
  actions?: ReactNode;
}) {
  const id = useId();
  return (
    <Field label={label} hint={hint} error={error} htmlFor={input.id ?? id}>
      <div className={`input-wrap ${large ? "input-lg" : ""} ${error ? "invalid" : ""}`}>
        {icon ? <Icon name={icon} className="input-icon" /> : null}
        <input id={input.id ?? id} spellCheck={false} autoComplete="off" {...input} />
        {actions ? <div className="input-actions">{actions}</div> : null}
      </div>
    </Field>
  );
}

/** A password input with a show/hide toggle (the value stays local). */
export function PasswordField({
  label,
  hint,
  error,
  large = false,
  extraActions,
  ...input
}: InputHTMLAttributes<HTMLInputElement> & {
  label: string;
  hint?: string;
  error?: string | null;
  large?: boolean;
  extraActions?: ReactNode;
}) {
  const { t } = useI18n();
  const [visible, setVisible] = useState(false);
  return (
    <TextField
      label={label}
      hint={hint}
      error={error}
      large={large}
      type={visible ? "text" : "password"}
      className={visible ? "mono" : undefined}
      autoComplete="off"
      autoCorrect="off"
      autoCapitalize="off"
      {...input}
      actions={
        <>
          {extraActions}
          <IconButton
            icon={visible ? "eyeOff" : "eye"}
            label={visible ? t("action.hide") : t("action.show")}
            onClick={() => setVisible((v) => !v)}
          />
        </>
      }
    />
  );
}

export function TextArea({
  label,
  hint,
  ...rest
}: TextareaHTMLAttributes<HTMLTextAreaElement> & { label: string; hint?: string }) {
  const id = useId();
  return (
    <Field label={label} hint={hint} htmlFor={rest.id ?? id}>
      <div className="input-wrap">
        <textarea id={rest.id ?? id} spellCheck={false} {...rest} />
      </div>
    </Field>
  );
}

export function Select({
  label,
  hint,
  options,
  hideLabel = false,
  ...rest
}: SelectHTMLAttributes<HTMLSelectElement> & {
  label: string;
  hint?: string;
  options: { value: string; label: string }[];
  hideLabel?: boolean;
}) {
  const id = useId();
  return (
    <Field label={label} hint={hint} htmlFor={rest.id ?? id} hideLabel={hideLabel}>
      <div className="input-wrap">
        <select id={rest.id ?? id} {...rest}>
          {options.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
        <Icon name="chevronDown" className="select-chevron" />
      </div>
    </Field>
  );
}

export function Toggle({
  label,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <label className="toggle">
      <input
        type="checkbox"
        role="switch"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span className="toggle-track" aria-hidden="true" />
      <span>{label}</span>
    </label>
  );
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T;
  options: { value: T; label: string; icon?: IconName }[];
  onChange: (value: T) => void;
  label: string;
}) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          aria-pressed={o.value === value}
          onClick={() => onChange(o.value)}
        >
          {o.icon ? <Icon name={o.icon} /> : null}
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function StrengthMeter({ level, bits }: { level: StrengthLevel; bits: number }) {
  const { t } = useI18n();
  return (
    <div className="strength" data-level={level}>
      <div className="strength-bar" aria-hidden="true">
        <span />
        <span />
        <span />
        <span />
        <span />
      </div>
      <div className="strength-label">
        <span>{t(`strength.${level}`)}</span>
        <span>{t("strength.bits", { bits: Math.round(bits) })}</span>
      </div>
    </div>
  );
}

export function Notice({
  tone = "neutral",
  icon = "info",
  children,
}: {
  tone?: "neutral" | "warning" | "danger" | "accent";
  icon?: IconName;
  children: ReactNode;
}) {
  return (
    <div className={`notice ${tone === "neutral" ? "" : `notice-${tone}`}`} role="note">
      <Icon name={icon} />
      <div>{children}</div>
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  text,
  action,
}: {
  icon: IconName;
  title: string;
  text?: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <Icon name={icon} />
      </div>
      <h3>{title}</h3>
      {text ? <p>{text}</p> : null}
      {action}
    </div>
  );
}
