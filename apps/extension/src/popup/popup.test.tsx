// The popup in every state, with a scripted background.

import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ConnectionState, PageView, PopupRequest, Reply } from "../shared/messages";
import type { PopupApi } from "./api";
import { catalogues } from "./i18n";
import { Popup } from "./Popup";

const LOGINS: PageView["logins"] = [
  { id: "a", title: "Example", username: "alice", matched: "exact_host", hasPassword: true, hasTotp: true, favorite: false },
  { id: "b", title: "Example (www)", username: null, matched: "same_site", hasPassword: true, hasTotp: false, favorite: false },
];

function view(patch: Partial<PageView> = {}): PageView {
  return {
    eligible: true,
    host: "example.com",
    internationalized: false,
    logins: LOGINS,
    pendingSave: null,
    hasLoginForm: true,
    hasNewPasswordField: false,
    detection: true,
    ...patch,
  };
}

function fakeApi(
  state: ConnectionState,
  answers: Partial<Record<PopupRequest["kind"], (r: PopupRequest) => Reply<unknown>>> = {},
  language = "en-US",
) {
  const requests: PopupRequest[] = [];
  let listener: (() => void) | null = null;
  const api: PopupApi & { closed: boolean; accessRequests: number } = {
    closed: false,
    accessRequests: 0,
    async request<T>(r: PopupRequest) {
      requests.push(r);
      const answer = answers[r.kind];
      if (answer) return answer(r) as Reply<T>;
      if (r.kind === "state") return { ok: true, value: state } as Reply<T>;
      if (r.kind === "page") return { ok: true, value: view() } as Reply<T>;
      return { ok: true, value: null } as Reply<T>;
    },
    async activeTabId() {
      return 42;
    },
    onStateChanged(cb) {
      listener = cb;
      return () => (listener = null);
    },
    close() {
      this.closed = true;
    },
    language: () => language,
    async requestHostAccess() {
      this.accessRequests += 1;
      return true;
    },
  };
  return { api, requests, changed: () => listener?.() };
}

describe("connection states", () => {
  it("explains how to reach the application", async () => {
    const { api, requests } = fakeApi({ state: "unavailable" });
    render(<Popup api={api} />);
    expect(await screen.findByText("Last Keys is not reachable")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => expect(requests.filter((r) => r.kind === "state")).toHaveLength(2));
  });

  it("pairs: shows the code to compare, then the logins once approved", async () => {
    let state: ConnectionState = { state: "unpaired" };
    const { api, changed } = fakeApi({ state: "unpaired" }, {
      state: () => ({ ok: true, value: state }),
      pair: () => ({ ok: true, value: { state: "pairing", code: "K7M-4QX" } }),
    });
    render(<Popup api={api} />);
    await userEvent.click(await screen.findByRole("button", { name: "Connect" }));
    expect(await screen.findByTestId("pairing-code")).toHaveTextContent("K7M-4QX");
    expect(screen.getByText("Confirm in Last Keys")).toBeInTheDocument();
    state = { state: "ready", locked: false };
    act(() => changed());
    expect(await screen.findByText("Example (www)")).toBeInTheDocument();
  });

  it("shows why a pairing failed", async () => {
    const { api } = fakeApi({ state: "unpaired", refused: "refused" });
    render(<Popup api={api} />);
    expect(await screen.findByText("The connection was refused in Last Keys.")).toBeInTheDocument();
  });

  it("asks to unlock in the application, never in the browser", async () => {
    const { api, requests } = fakeApi({ state: "ready", locked: true });
    render(<Popup api={api} />);
    await userEvent.click(await screen.findByRole("button", { name: "Unlock in Last Keys" }));
    expect(requests.some((r) => r.kind === "focus")).toBe(true);
    expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument();
    expect(document.querySelector("input")).toBeNull();
  });

  it("is translated into French", async () => {
    const { api } = fakeApi({ state: "ready", locked: true }, {}, "fr-FR");
    render(<Popup api={api} />);
    expect(await screen.findByText("Last Keys est verrouillé")).toBeInTheDocument();
  });
});

describe("logins of the page", () => {
  it("fills a login and closes", async () => {
    const { api, requests } = fakeApi({ state: "ready", locked: false }, {
      fill: () => ({ ok: true, value: { filled: 2 } }),
    });
    render(<Popup api={api} />);
    const row = (await screen.findByText("Example")).closest("li");
    if (!row) throw new Error("no row");
    expect(within(row).getByText("alice")).toBeInTheDocument();
    await userEvent.click(within(row).getByRole("button", { name: "Fill" }));
    expect(requests).toContainEqual({ kind: "fill", tabId: 42, itemId: "a" });
    await waitFor(() => expect(api.closed).toBe(true));
    expect(screen.getByText("Same site")).toBeInTheDocument();
  });

  it("asks before filling an embedded form of another origin", async () => {
    const { api, requests } = fakeApi({ state: "ready", locked: false }, {
      fill: (r) =>
        r.kind === "fill" && r.confirmFrame === 3
          ? { ok: true, value: { filled: 1 } }
          : { ok: true, value: { confirm: { frameId: 3, frameHost: "login.example.com" } } },
    });
    render(<Popup api={api} />);
    const row = (await screen.findByText("Example")).closest("li");
    if (!row) throw new Error("no row");
    await userEvent.click(within(row).getByRole("button", { name: "Fill" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Fill an embedded form?" });
    expect(dialog).toHaveTextContent("login.example.com");
    expect(api.closed).toBe(false);
    await userEvent.click(within(dialog).getByRole("button", { name: "Fill anyway" }));
    expect(requests).toContainEqual({ kind: "fill", tabId: 42, itemId: "a", confirmFrame: 3 });
    await waitFor(() => expect(api.closed).toBe(true));
  });

  it("says when there is nothing to fill or the login does not match", async () => {
    let answer: Reply<unknown> = { ok: true, value: { filled: 0 } };
    const { api } = fakeApi({ state: "ready", locked: false }, { fill: () => answer });
    render(<Popup api={api} />);
    const row = (await screen.findByText("Example")).closest("li");
    if (!row) throw new Error("no row");
    await userEvent.click(within(row).getByRole("button", { name: "Fill" }));
    expect(await screen.findByText("No field to fill was found on this page.")).toBeInTheDocument();
    answer = { ok: false, code: "origin_mismatch" };
    await userEvent.click(within(row).getByRole("button", { name: "Fill" }));
    expect(await screen.findByText("This login does not belong to this website.")).toBeInTheDocument();
    expect(api.closed).toBe(false);
  });

  it("copies through the application", async () => {
    const { api, requests } = fakeApi({ state: "ready", locked: false }, {
      copy: () => ({ ok: true, value: { clearsInSeconds: 30 } }),
    });
    render(<Popup api={api} />);
    await userEvent.click(await screen.findByRole("button", { name: "Copy code · Example" }));
    expect(requests).toContainEqual({ kind: "copy", tabId: 42, itemId: "a", field: "totp" });
    expect(await screen.findByText("Copied. The clipboard is cleared in 30 s.")).toBeInTheDocument();
    // No username: no button to copy it.
    expect(screen.queryByRole("button", { name: "Copy username · Example (www)" })).not.toBeInTheDocument();
  });

  it("explains an empty list, an ineligible page and look-alike addresses", async () => {
    const empty = fakeApi({ state: "ready", locked: false }, {
      page: () => ({ ok: true, value: view({ logins: [], internationalized: true, host: "xn--pple-43d.com" }) }),
    });
    const { unmount } = render(<Popup api={empty.api} />);
    expect(await screen.findByText("No login saved for this site.")).toBeInTheDocument();
    expect(screen.getByText("International address: check that this is the site you expect.")).toBeInTheDocument();
    unmount();
    const other = fakeApi({ state: "ready", locked: false }, {
      page: () => ({ ok: true, value: view({ eligible: false, host: null, logins: [] }) }),
    });
    render(<Popup api={other.api} />);
    expect(await screen.findByText("Last Keys does not fill this kind of page.")).toBeInTheDocument();
  });
});

describe("host access (AUDIT P-9)", () => {
  it("proposes access to every site when it is not granted", async () => {
    let granted = false;
    const { api } = fakeApi({ state: "ready", locked: false }, {
      page: () => ({ ok: true, value: view({ detection: granted }) }),
    });
    api.requestHostAccess = async function () {
      this.accessRequests += 1;
      granted = true;
      return true;
    };
    render(<Popup api={api} />);
    const card = await screen.findByRole("region", { name: "Detect login forms on every site" });
    // The logins of the page are offered anyway (click-to-fill).
    expect(screen.getByText("Example")).toBeInTheDocument();
    await userEvent.click(within(card).getByRole("button", { name: "Allow" }));
    expect(api.accessRequests).toBe(1);
    await waitFor(() =>
      expect(screen.queryByRole("region", { name: "Detect login forms on every site" })).not.toBeInTheDocument(),
    );
  });
});

describe("saving and generating", () => {
  it("offers to save new credentials", async () => {
    let pending: PageView["pendingSave"] = {
      host: "shop.example.net",
      username: "carol",
      proposal: { action: "new", title: "example.net", url: "https://shop.example.net/" },
    };
    const { api, requests } = fakeApi({ state: "ready", locked: false }, {
      page: () => ({ ok: true, value: view({ pendingSave: pending }) }),
      save: () => {
        pending = null;
        return { ok: true, value: null };
      },
    });
    render(<Popup api={api} />);
    expect(await screen.findByText("Save this login?")).toBeInTheDocument();
    expect(screen.getByText("carol")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(requests).toContainEqual({ kind: "save", tabId: 42 });
    expect(await screen.findByText("Saved in Last Keys.")).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByText("Save this login?")).not.toBeInTheDocument());
  });

  it("offers to update a password, or waits for the unlock", async () => {
    const update = fakeApi({ state: "ready", locked: false }, {
      page: () => ({
        ok: true,
        value: view({ pendingSave: { host: "example.com", username: "alice", proposal: { action: "update_password", id: "a", title: "Example" } } }),
      }),
    });
    const { unmount } = render(<Popup api={update.api} />);
    expect(await screen.findByText("Update the password of “Example”?")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Not now" }));
    expect(update.requests).toContainEqual({ kind: "dismissSave", tabId: 42 });
    unmount();
    const waiting = fakeApi({ state: "ready", locked: false }, {
      page: () => ({ ok: true, value: view({ pendingSave: { host: "example.com", username: null, proposal: null } }) }),
    });
    render(<Popup api={waiting.api} />);
    expect(await screen.findByText("Login submitted on example.com")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save" })).not.toBeInTheDocument();
  });

  it("generates a password and fills it", async () => {
    const { api, requests } = fakeApi({ state: "ready", locked: false }, {
      generate: () => ({ ok: true, value: { password: "Xy7!generated-pw" } }),
      fillGenerated: () => ({ ok: true, value: { filled: 2 } }),
    });
    render(<Popup api={api} />);
    await userEvent.click(await screen.findByRole("button", { name: "Generate a password" }));
    expect(await screen.findByTestId("generated")).toHaveTextContent("Xy7!generated-pw");
    await userEvent.click(within(screen.getByTestId("generated").parentElement as HTMLElement).getByRole("button", { name: "Fill" }));
    expect(requests).toContainEqual({ kind: "fillGenerated", tabId: 42, password: "Xy7!generated-pw" });
    await waitFor(() => expect(api.closed).toBe(true));
  });
});

describe("translations", () => {
  it("define the same keys and placeholders in French", () => {
    const en = catalogues.en as Record<string, string>;
    const fr = catalogues.fr as Record<string, string>;
    expect(Object.keys(fr).sort()).toEqual(Object.keys(en).sort());
    const vars = (s: string) => (s.match(/\{\w+\}/g) ?? []).sort();
    for (const key of Object.keys(en)) expect(vars(fr[key] ?? ""), key).toEqual(vars(en[key] ?? ""));
  });
});
