// Item list (search, keyboard navigation) and the detail or editor pane.

import { useCallback, useEffect, useRef, useState } from "react";
import type { ItemKind, ItemSummary } from "../api/types";
import { Button, EmptyState, IconButton } from "../components/controls";
import { Icon } from "../components/Icon";
import { ItemAvatar, kindIcon, kindLabel } from "../components/ItemAvatar";
import { useI18n, type MessageKey } from "../i18n";
import { useApp } from "../state/app";
import { ItemDetail } from "./ItemDetail";
import { ItemEditor } from "./ItemEditor";
import type { Filter } from "./Shell";

type Mode = { kind: "view" } | { kind: "edit" } | { kind: "create"; itemKind: ItemKind } | { kind: "pick" };

const FILTER_TITLE: Record<Filter, MessageKey> = {
  all: "nav.all",
  favorites: "nav.favorites",
  login: "nav.logins",
  secure_note: "nav.notes",
  payment_card: "nav.cards",
  identity: "nav.identities",
};

export function VaultView({
  filter,
  matches,
  version,
  onLocalChange,
}: {
  filter: Filter;
  matches: (item: ItemSummary) => boolean;
  version: number;
  onLocalChange: () => void;
}) {
  const { t } = useI18n();
  const { backend, errorText, toast } = useApp();
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [mode, setMode] = useState<Mode>({ kind: "view" });
  const search = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLUListElement>(null);

  useEffect(() => {
    let cancelled = false;
    backend
      .listItems(query)
      .then((rows) => {
        if (!cancelled) setItems(rows.filter(matches));
      })
      .catch((err: unknown) => toast(errorText(err), "error"));
    return () => {
      cancelled = true;
    };
    // `matches` changes with `filter`.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [backend, query, filter, version]);

  // The selection falls back to the first item when it is not in the list.
  const current =
    selected && items.some((i) => i.id === selected) ? selected : (items[0]?.id ?? null);

  const newItem = useCallback(() => {
    if (filter === "all" || filter === "favorites") setMode({ kind: "pick" });
    else setMode({ kind: "create", itemKind: filter });
  }, [filter]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey)) return;
      const key = e.key.toLowerCase();
      if (key === "f") {
        e.preventDefault();
        search.current?.focus();
      } else if (key === "n") {
        e.preventDefault();
        newItem();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [newItem]);

  const moveSelection = (delta: number) => {
    const index = items.findIndex((i) => i.id === current);
    const next = items[Math.min(Math.max(index + delta, 0), items.length - 1)];
    if (next) {
      setSelected(next.id);
      setMode({ kind: "view" });
      list.current?.querySelector<HTMLElement>(`[data-id="${next.id}"]`)?.focus();
    }
  };

  const saved = (id: string) => {
    setSelected(id);
    setMode({ kind: "view" });
    onLocalChange();
  };

  return (
    <div className="vault">
      <section className="list-pane" aria-label={t(FILTER_TITLE[filter])}>
        <div className="list-header">
          <div className="input-wrap">
            <Icon name="search" className="input-icon" />
            <input
              ref={search}
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder={t("vault.search")}
              aria-label={t("vault.search")}
              spellCheck={false}
              onKeyDown={(e) => {
                if (e.key === "ArrowDown") {
                  e.preventDefault();
                  moveSelection(items.findIndex((i) => i.id === current) < 0 ? 0 : 1);
                }
              }}
            />
          </div>
          <IconButton icon="plus" label={t("vault.new")} onClick={newItem} />
        </div>
        <div className="list-title">
          <span>{t(FILTER_TITLE[filter])}</span>
          <span>{items.length}</span>
        </div>
        {items.length === 0 ? (
          <EmptyState
            icon={query ? "search" : "key"}
            title={query ? t("vault.noResults") : t("vault.empty")}
            text={query ? t("vault.noResultsHint") : t("vault.emptyHint")}
            action={
              query ? undefined : (
                <Button variant="primary" icon="plus" onClick={newItem}>
                  {t("vault.new")}
                </Button>
              )
            }
          />
        ) : (
          <ul
            className="item-list"
            ref={list}
            role="listbox"
            aria-label={t(FILTER_TITLE[filter])}
            onKeyDown={(e) => {
              if (e.key === "ArrowDown") {
                e.preventDefault();
                moveSelection(1);
              } else if (e.key === "ArrowUp") {
                e.preventDefault();
                moveSelection(-1);
              }
            }}
          >
            {items.map((item) => (
              <li
                key={item.id}
                data-id={item.id}
                className="item-row"
                role="option"
                aria-selected={item.id === current && mode.kind === "view"}
                tabIndex={item.id === current ? 0 : -1}
                onClick={() => {
                  setSelected(item.id);
                  setMode({ kind: "view" });
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter") setMode({ kind: "edit" });
                }}
              >
                <ItemAvatar kind={item.kind} title={item.title} />
                <div className="item-row-text">
                  <div className="item-row-title">{item.title}</div>
                  <div className="item-row-sub">
                    {item.subtitle ?? item.host ?? t(kindLabel[item.kind])}
                  </div>
                </div>
                {item.favorite ? <Icon name="star" filled className="star" /> : null}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section className="detail-pane" aria-live="polite">
        {mode.kind === "pick" ? (
          <TypePicker
            onPick={(itemKind) => setMode({ kind: "create", itemKind })}
            onCancel={() => setMode({ kind: "view" })}
          />
        ) : mode.kind === "create" ? (
          <ItemEditor
            key={`new-${mode.itemKind}`}
            kind={mode.itemKind}
            onCancel={() => setMode({ kind: "view" })}
            onSaved={saved}
          />
        ) : current && mode.kind === "edit" ? (
          <ItemEditor
            key={`edit-${current}`}
            itemId={current}
            onCancel={() => setMode({ kind: "view" })}
            onSaved={saved}
          />
        ) : current ? (
          <ItemDetail
            key={current}
            itemId={current}
            version={version}
            onEdit={() => setMode({ kind: "edit" })}
            onChanged={onLocalChange}
            onDeleted={() => {
              setSelected(null);
              onLocalChange();
            }}
          />
        ) : (
          <EmptyState icon="shield" title={t("vault.selectTitle")} text={t("vault.selectHint")} />
        )}
      </section>
    </div>
  );
}

function TypePicker({ onPick, onCancel }: { onPick: (kind: ItemKind) => void; onCancel: () => void }) {
  const { t } = useI18n();
  const kinds: { kind: ItemKind; hint: MessageKey }[] = [
    { kind: "login", hint: "picker.loginHint" },
    { kind: "secure_note", hint: "picker.noteHint" },
    { kind: "payment_card", hint: "picker.cardHint" },
    { kind: "identity", hint: "picker.identityHint" },
  ];
  return (
    <div className="editor">
      <div className="editor-header">
        <h2>{t("picker.title")}</h2>
        <Button variant="ghost" onClick={onCancel}>
          {t("action.cancel")}
        </Button>
      </div>
      <div className="type-picker">
        {kinds.map(({ kind, hint }) => (
          <button key={kind} type="button" className="choice" onClick={() => onPick(kind)}>
            <span className="choice-icon">
              <Icon name={kindIcon[kind]} />
            </span>
            <span>
              <strong>{t(kindLabel[kind])}</strong>
              <span>{t(hint)}</span>
            </span>
          </button>
        ))}
      </div>
    </div>
  );
}
