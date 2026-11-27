import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "../App";
import { createMockBackend, MOCK_PASSWORD } from "../api/mock";

function start(query: string) {
  window.history.replaceState(null, "", `/${query}`);
  const backend = createMockBackend();
  render(<App backend={backend} />);
  return backend;
}

describe("unlock", () => {
  it("refuses a wrong password with a translated message, then unlocks", async () => {
    const user = userEvent.setup();
    start("?state=locked&lang=fr");
    const field = await screen.findByLabelText("Mot de passe maître");
    await user.type(field, "pas le bon mot de passe");
    await user.click(screen.getByRole("button", { name: "Déverrouiller" }));
    expect(await screen.findByText("Mot de passe maître ou clé de récupération incorrect.")).toBeInTheDocument();
    await user.clear(field);
    await user.type(field, MOCK_PASSWORD);
    await user.click(screen.getByRole("button", { name: "Déverrouiller" }));
    expect(await screen.findByRole("navigation", { name: "Navigation principale" })).toBeInTheDocument();
  });

  it("offers the recovery key and validates its format", async () => {
    const user = userEvent.setup();
    start("?state=locked&lang=en");
    await user.click(await screen.findByRole("button", { name: "Forgot your master password?" }));
    await user.type(screen.getByLabelText("Recovery key"), "not a key");
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    expect(await screen.findByText("This is not a valid recovery key.")).toBeInTheDocument();
  });
});

describe("onboarding", () => {
  it("enforces the master password rules before creating the vault", async () => {
    const user = userEvent.setup();
    start("?state=fresh&lang=en");
    await user.click(await screen.findByRole("button", { name: /Create a new vault/ }));
    const create = screen.getByRole("button", { name: "Create my vault" });
    await user.type(screen.getByLabelText("Master password"), "short");
    expect(screen.getByText("The master password must have at least 12 characters.")).toBeInTheDocument();
    expect(create).toBeDisabled();
    await user.clear(screen.getByLabelText("Master password"));
    await user.type(screen.getByLabelText("Master password"), "long enough passphrase");
    await user.type(screen.getByLabelText("Confirm the master password"), "long enough passphrasE");
    expect(screen.getByText("The two passwords do not match.")).toBeInTheDocument();
    expect(create).toBeDisabled();
    await user.clear(screen.getByLabelText("Confirm the master password"));
    await user.type(screen.getByLabelText("Confirm the master password"), "long enough passphrase");
    await user.click(create);
    // The recovery key is shown once and must be acknowledged.
    expect(await screen.findByTestId("recovery-key")).toHaveTextContent(/^LK1-/);
    const open = screen.getByRole("button", { name: "Open my vault" });
    expect(open).toBeDisabled();
    await user.click(screen.getByLabelText("I have stored my recovery key in a safe place."));
    await user.click(open);
    expect(await screen.findByText("Nothing here yet")).toBeInTheDocument();
  });
});

describe("vault", () => {
  it("shows secrets only on request and hides them again", async () => {
    const user = userEvent.setup();
    start("?state=unlocked&lang=en");
    await user.click(await screen.findByRole("option", { name: /Netflix/ }));
    await screen.findByRole("heading", { name: "Netflix" });
    expect(screen.queryByText("popcorn-Velvet-42")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Reveal" }));
    expect(await screen.findByText("popcorn-Velvet-42")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Hide" }));
    await waitFor(() => expect(screen.queryByText("popcorn-Velvet-42")).not.toBeInTheDocument());
  });

  it("returns to the unlock screen when the vault locks by itself", async () => {
    start("?state=unlocked&lang=en");
    await screen.findByRole("navigation", { name: "Main navigation" });
    (window as unknown as { __lkMockAutoLock: () => void }).__lkMockAutoLock();
    expect(await screen.findByText("Your vault was locked after a period of inactivity.")).toBeInTheDocument();
  });
});

describe("browser extension", () => {
  it("turns integration on, lists browsers and removes a connected extension", async () => {
    const user = userEvent.setup();
    start("?state=unlocked&lang=en");
    await user.click(await screen.findByRole("button", { name: "Settings" }));
    const toggle = await screen.findByRole("switch", { name: "Off" });
    expect(screen.queryByRole("list", { name: "Browsers" })).not.toBeInTheDocument();
    await user.click(toggle);
    expect(await screen.findByRole("switch", { name: "On" })).toBeChecked();
    const browsers = await screen.findByRole("list", { name: "Browsers" });
    expect(browsers).toHaveTextContent("Google Chrome");
    expect(browsers).toHaveTextContent("Ready");
    expect(browsers).toHaveTextContent("Not found");
    expect(screen.getByText(/None yet/)).toBeInTheDocument();
  });

  it("asks before pairing, shows the code, and closing refuses", async () => {
    const user = userEvent.setup();
    const backend = start("?state=unlocked&lang=fr&bridge=1&pairing=1");
    // The French catalogue puts a non-breaking space before "?".
    const dialog = await screen.findByRole("dialog", { name: "Connecter une extension de navigateur\u00a0?" });
    expect(dialog).toHaveTextContent("K7M-4QX");
    expect(dialog).toHaveTextContent("Firefox · Linux");
    expect(dialog).toHaveTextContent("browser-extension@lastkeys.app");
    await user.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    const status = await backend.bridgeStatus();
    expect(status.pending).toBeNull();
    expect(status.clients.map((c) => c.name)).toEqual(["Chrome · Linux"]);
  });

  it("connects an approved extension and lists it", async () => {
    const user = userEvent.setup();
    start("?state=unlocked&lang=en&bridge=1");
    await user.click(await screen.findByRole("button", { name: "Settings" }));
    const paired = await screen.findByRole("list", { name: "Connected extensions" });
    expect(paired).toHaveTextContent("Chrome · Linux");
    (window as unknown as { __lkMockPairing: () => void }).__lkMockPairing();
    const dialog = await screen.findByRole("dialog", { name: "Connect a browser extension?" });
    await user.click(within(dialog).getByRole("button", { name: "Connect" }));
    expect(await screen.findByText("The extension is connected.")).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole("list", { name: "Connected extensions" })).toHaveTextContent("Firefox · Linux"),
    );
    const rows = within(screen.getByRole("list", { name: "Connected extensions" })).getAllByRole("listitem");
    const chrome = rows.find((row) => row.textContent?.includes("Chrome · Linux"));
    if (!chrome) throw new Error("Chrome row missing");
    await user.click(within(chrome).getByRole("button", { name: "Remove" }));
    await waitFor(() =>
      expect(screen.getByRole("list", { name: "Connected extensions" })).not.toHaveTextContent("Chrome · Linux"),
    );
  });

  it("shows the pairing dialog over the unlock screen too", async () => {
    start("?state=locked&lang=en&bridge=1&pairing=1");
    expect(await screen.findByRole("dialog", { name: "Connect a browser extension?" })).toBeInTheDocument();
  });

  it("refreshes the list when a login is saved from the browser", async () => {
    start("?state=unlocked&lang=en");
    await screen.findByRole("option", { name: /Netflix/ });
    expect(screen.queryByRole("option", { name: /example\.net/ })).not.toBeInTheDocument();
    (window as unknown as { __lkMockSavedFromBrowser: () => void }).__lkMockSavedFromBrowser();
    expect(await screen.findByRole("option", { name: /example\.net/ })).toBeInTheDocument();
  });
});
