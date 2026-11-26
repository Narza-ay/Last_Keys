import type { ItemKind } from "../api/types";
import type { MessageKey } from "../i18n";
import { Icon, type IconName } from "./Icon";

export const kindIcon: Record<ItemKind, IconName> = {
  login: "globe",
  secure_note: "note",
  payment_card: "card",
  identity: "identity",
};

export const kindLabel: Record<ItemKind, MessageKey> = {
  login: "kind.login",
  secure_note: "kind.secure_note",
  payment_card: "kind.payment_card",
  identity: "kind.identity",
};

const PALETTE = [
  "#5848e5",
  "#2f7de1",
  "#0f9b8e",
  "#188a5c",
  "#c2410c",
  "#d33a4b",
  "#b4297a",
  "#7c3aed",
];

/** A stable colour for a title (same title, same colour). */
export function colorFor(text: string): string {
  let hash = 0;
  for (const ch of text) hash = (hash * 31 + (ch.codePointAt(0) ?? 0)) >>> 0;
  return PALETTE[hash % PALETTE.length] ?? "#5848e5";
}

export function ItemAvatar({
  kind,
  title,
  large = false,
}: {
  kind: ItemKind;
  title: string;
  large?: boolean;
}) {
  const initial = Array.from(title.trim())[0];
  const showInitial = kind === "login" && initial !== undefined && /\p{L}|\p{N}/u.test(initial);
  return (
    <span
      className={`avatar ${large ? "avatar-lg" : ""}`}
      style={{ background: colorFor(title) }}
      aria-hidden="true"
    >
      {showInitial ? initial : <Icon name={kindIcon[kind]} />}
    </span>
  );
}
