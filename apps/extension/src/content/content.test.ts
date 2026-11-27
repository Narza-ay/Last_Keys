// Form detection, filling and capture on representative pages.

import { submissionFrom, watchSubmissions, type Submission } from "./capture";
import { detect, summarize } from "./detect";
import { fillLogin, fillNewPassword } from "./fill";

function page(html: string): Document {
  document.body.replaceChildren();
  const template = document.createElement("template");
  // Test fixtures only (the lint rule forbids this in the extension).
  template.innerHTML = html;
  document.body.append(template.content);
  return document;
}

const byId = (id: string) => document.getElementById(id) as HTMLInputElement;

describe("detection", () => {
  it("finds the username and password of a classic login form", () => {
    page(`
      <form>
        <input type="search" id="search" name="q">
        <label for="user">E-mail</label><input type="email" id="user">
        <input type="password" id="pw" name="password">
        <button type="submit">Sign in</button>
      </form>`);
    const fields = detect(document);
    expect(fields.username?.id).toBe("user");
    expect(fields.password?.id).toBe("pw");
    expect(fields.newPasswords).toEqual([]);
    expect(summarize(fields)).toEqual({ login: true, newPassword: false, otp: false });
  });

  it("prefers a tagged username field over another text field", () => {
    page(`
      <form>
        <input type="text" id="user" autocomplete="username">
        <input type="text" id="other" name="coupon">
        <input type="password" id="pw">
      </form>`);
    expect(detect(document).username?.id).toBe("user");
  });

  it("recognises a username-only first step", () => {
    page(`<form><input type="email" id="id" autocomplete="username"><button>Next</button></form>`);
    const fields = detect(document);
    expect(fields.username?.id).toBe("id");
    expect(fields.password).toBeNull();
    expect(summarize(fields).login).toBe(true);
  });

  it("separates current and new passwords", () => {
    page(`
      <form>
        <input type="password" id="current" autocomplete="current-password">
        <input type="password" id="new" autocomplete="new-password">
        <input type="password" id="confirm" name="confirm_password">
      </form>`);
    const fields = detect(document);
    expect(fields.password?.id).toBe("current");
    expect(fields.newPasswords.map((i) => i.id)).toEqual(["new", "confirm"]);
  });

  it("treats a password and its confirmation as a registration form", () => {
    page(`
      <form>
        <input type="email" id="email" name="email">
        <input type="password" id="p1">
        <input type="password" id="p2">
      </form>`);
    const fields = detect(document);
    expect(fields.password?.id).toBe("p1");
    expect(fields.newPasswords.map((i) => i.id)).toEqual(["p2"]);
    expect(fields.username?.id).toBe("email");
  });

  it("finds one-time code fields", () => {
    page(`<input type="text" id="code" autocomplete="one-time-code" inputmode="numeric">`);
    expect(detect(document).otp?.id).toBe("code");
    page(`<input type="text" id="totp" name="totp" maxlength="6">`);
    expect(detect(document).otp?.id).toBe("totp");
    page(`<input type="text" id="name" name="name">`);
    expect(detect(document).otp).toBeNull();
  });

  it("does not take an unrelated text field for a username", () => {
    page(`<form><input type="search" id="q" name="q"><input type="text" id="city" name="city"></form>`);
    expect(detect(document).username).toBeNull();
    page(`<form><input type="text" id="u" name="username"></form>`);
    expect(detect(document).username?.id).toBe("u");
  });

  it("works without a form element", () => {
    page(`<div><input type="text" id="u" name="login"><input type="password" id="p"><div role="button">Log in</div></div>`);
    const fields = detect(document);
    expect(fields.username?.id).toBe("u");
    expect(fields.password?.id).toBe("p");
  });

  it("ignores hidden, off-screen, disabled and read-only fields", () => {
    page(`
      <form>
        <input type="text" id="trap1" name="username" style="display:none">
        <div style="visibility:hidden"><input type="text" id="trap2" name="username"></div>
        <input type="text" id="trap3" name="username" style="opacity:0">
        <input type="text" id="trap4" name="username" data-rect="zero">
        <input type="text" id="trap5" name="username" data-rect="offscreen">
        <input type="text" id="trap6" name="username" aria-hidden="true">
        <input type="password" id="trap7" disabled>
        <input type="password" id="trap8" readonly>
        <input type="hidden" id="trap9" name="password">
      </form>`);
    const fields = detect(document);
    expect(fields.username).toBeNull();
    expect(fields.password).toBeNull();
    expect(summarize(fields)).toEqual({ login: false, newPassword: false, otp: false });
  });
});

describe("filling", () => {
  it("writes values with input and change events", () => {
    page(`<form><input type="text" id="u" name="user"><input type="password" id="p"><input type="text" id="c" autocomplete="one-time-code"></form>`);
    const events: string[] = [];
    for (const id of ["u", "p", "c"]) {
      byId(id).addEventListener("input", (e) => events.push(`input:${(e.target as HTMLInputElement).id}`));
      byId(id).addEventListener("change", (e) => events.push(`change:${(e.target as HTMLInputElement).id}`));
    }
    const filled = fillLogin(detect(document), { username: "alice", password: "s3cret", totp: "123456" });
    expect(filled).toBe(3);
    expect(byId("u").value).toBe("alice");
    expect(byId("p").value).toBe("s3cret");
    expect(byId("c").value).toBe("123456");
    expect(events).toEqual(["input:u", "change:u", "input:p", "change:p", "input:c", "change:c"]);
  });

  it("never writes into hidden fields", () => {
    page(`
      <form>
        <input type="text" id="u" name="user">
        <input type="text" id="trap" name="email" style="display:none">
        <input type="password" id="trapPw" style="opacity:0">
      </form>`);
    const filled = fillLogin(detect(document), { username: "alice", password: "s3cret", totp: null });
    expect(filled).toBe(1);
    expect(byId("trap").value).toBe("");
    expect(byId("trapPw").value).toBe("");
  });

  it("fills a generated password into new-password fields only", () => {
    page(`
      <form>
        <input type="password" id="current" autocomplete="current-password">
        <input type="password" id="new" autocomplete="new-password">
        <input type="password" id="confirm" autocomplete="new-password">
      </form>`);
    expect(fillNewPassword(detect(document), "G3n-erated")).toBe(2);
    expect(byId("current").value).toBe("");
    expect(byId("new").value).toBe("G3n-erated");
    expect(byId("confirm").value).toBe("G3n-erated");
  });
});

describe("capture", () => {
  it("reads the submitted username and password", () => {
    page(`<form><input type="email" id="u"><input type="password" id="p"></form>`);
    byId("u").value = " alice@example.com ";
    byId("p").value = "s3cret";
    expect(submissionFrom(detect(document))).toEqual({ username: "alice@example.com", password: "s3cret" });
  });

  it("saves the new password of a change form, nothing for an empty one", () => {
    page(`
      <form>
        <input type="password" id="current" autocomplete="current-password">
        <input type="password" id="new" autocomplete="new-password">
      </form>`);
    byId("current").value = "old";
    byId("new").value = "brand-new";
    expect(submissionFrom(detect(document))).toEqual({ username: null, password: "brand-new" });
    byId("current").value = "";
    byId("new").value = "";
    expect(submissionFrom(detect(document))).toBeNull();
  });

  it("reports on submit, on a submit button and on Enter, once per submission", () => {
    page(`
      <form id="f" onsubmit="return false">
        <input type="text" id="u" name="username">
        <input type="password" id="p">
        <button type="submit" id="go">Sign in</button>
        <button type="button" id="show">Show</button>
      </form>`);
    const seen: Submission[] = [];
    const stop = watchSubmissions(document, (s) => seen.push(s));
    byId("u").value = "alice";
    byId("p").value = "pw-1";
    document.getElementById("show")?.click();
    expect(seen).toEqual([]);
    document.getElementById("go")?.click();
    document.getElementById("f")?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
    expect(seen).toEqual([{ username: "alice", password: "pw-1" }]);
    byId("p").value = "pw-2";
    byId("p").dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    expect(seen).toEqual([
      { username: "alice", password: "pw-1" },
      { username: "alice", password: "pw-2" },
    ]);
    stop();
    byId("p").value = "pw-3";
    document.getElementById("go")?.click();
    expect(seen).toHaveLength(2);
  });
});
