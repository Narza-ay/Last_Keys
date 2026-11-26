import { render, screen, waitFor } from "@testing-library/react";
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
