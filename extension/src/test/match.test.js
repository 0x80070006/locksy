// Correspondance stricte identifiant ↔ page (node --test src/test/).
import { test } from "node:test";
import assert from "node:assert/strict";
import { registrableDomain, urlMatches, matchStatus, isInsecurePage, webPage } from "../match.js";

test("domaine enregistrable : cas courants", () => {
  assert.equal(registrableDomain("login.example.com"), "example.com");
  assert.equal(registrableDomain("example.com"), "example.com");
  assert.equal(registrableDomain("A.B.Example.COM."), "example.com");
  assert.equal(registrableDomain("www.bbc.co.uk"), "bbc.co.uk");
  assert.equal(registrableDomain("impots.gouv.fr"), "impots.gouv.fr");
  assert.equal(registrableDomain("www.impots.gouv.fr"), "impots.gouv.fr");
  assert.equal(registrableDomain("alice.github.io"), "alice.github.io");
  assert.equal(registrableDomain("docs.alice.github.io"), "alice.github.io");
  assert.equal(registrableDomain("bucket.s3.amazonaws.com"), "bucket.s3.amazonaws.com");
  assert.equal(registrableDomain("github.io"), "github.io");
  assert.equal(registrableDomain("co.uk"), "co.uk");
});

test("domaine enregistrable : IP, localhost et ccSLD inconnu donnent l'hôte exact", () => {
  assert.equal(registrableDomain("192.168.1.10"), "192.168.1.10");
  assert.equal(registrableDomain("[::1]"), "[::1]");
  assert.equal(registrableDomain("[2001:db8::1]"), "[2001:db8::1]");
  assert.equal(registrableDomain("localhost"), "localhost");
  assert.equal(registrableDomain("app.localhost"), "app.localhost");
  assert.equal(registrableDomain("intranet"), "intranet");
  assert.equal(registrableDomain("x.co.ke"), "x.co.ke");
  assert.equal(registrableDomain("a.b.co.ke"), "a.b.co.ke");
  // « www. » de tête retiré sous la règle prudente.
  assert.equal(registrableDomain("www.sfr.fr"), "sfr.fr");
  assert.equal(registrableDomain(""), "");
});

test("même origine et sous-domaines du même site", () => {
  assert.ok(urlMatches("https://example.com/login", "https://example.com/account"));
  assert.ok(urlMatches("https://login.example.com", "https://example.com/"));
  assert.ok(urlMatches("https://example.com", "https://login.example.com/x"));
  assert.ok(urlMatches("example.com", "https://www.example.com/"), "sans schéma = https");
  assert.ok(urlMatches("https://sfr.fr", "https://www.sfr.fr/"));
});

test("sites piégés refusés", () => {
  assert.equal(urlMatches("https://example.com", "https://example.com.evil.com/"), false);
  assert.equal(urlMatches("https://example.com", "https://evil-example.com/"), false);
  assert.equal(urlMatches("https://example.com", "https://notexample.com/"), false);
  assert.equal(urlMatches("https://a.co.uk", "https://b.co.uk/"), false);
  assert.equal(urlMatches("https://alice.github.io", "https://bob.github.io/"), false);
  assert.equal(urlMatches("https://x.co.ke", "https://y.co.ke/"), false);
  assert.equal(urlMatches("https://myapp.vercel.app", "https://evil.vercel.app/"), false);
});

test("http et https : montée autorisée, descente refusée", () => {
  assert.ok(urlMatches("http://example.com", "https://example.com/"));
  assert.equal(urlMatches("https://example.com", "http://example.com/"), false);
  assert.equal(matchStatus("https://example.com", "http://example.com/"), "downgrade");
  assert.ok(urlMatches("http://example.com", "http://example.com/"));
  assert.equal(matchStatus("https://example.com", "https://other.com/"), "nomatch");
});

test("ports effectifs", () => {
  assert.ok(urlMatches("https://example.com:8443", "https://example.com:8443/"));
  assert.equal(urlMatches("https://example.com:8443", "https://example.com/"), false);
  assert.equal(urlMatches("https://example.com", "https://example.com:8443/"), false);
  assert.ok(urlMatches("https://example.com:443", "https://example.com/"), "443 implicite");
  assert.ok(urlMatches("http://example.com:80", "https://example.com/"), "80 implicite → 443 implicite");
  assert.equal(urlMatches("http://example.com:8080", "https://example.com/"), false);
  assert.equal(urlMatches("http://localhost:3000", "http://localhost:4000/"), false);
  assert.ok(urlMatches("http://localhost:3000", "http://localhost:3000/login"));
});

test("adresses IP voisines refusées", () => {
  assert.equal(urlMatches("https://192.168.1.10", "https://192.168.1.11/"), false);
  assert.ok(urlMatches("https://192.168.1.10", "https://192.168.1.10/admin"));
  assert.equal(urlMatches("https://10.0.0.1", "https://1.0.0.1/"), false);
  assert.equal(urlMatches("https://[::1]:8443", "https://[::2]:8443/"), false);
});

test("majuscules, point final et IDN", () => {
  assert.ok(urlMatches("HTTPS://Login.EXAMPLE.com", "https://example.com/"));
  assert.ok(urlMatches("https://example.com.", "https://www.example.com/"));
  assert.ok(urlMatches("https://bücher.de", "https://www.xn--bcher-kva.de/"));
  assert.equal(urlMatches("https://bücher.de", "https://bucher.de/"), false);
});

test("schémas non web refusés", () => {
  assert.equal(urlMatches("data:text/html,x", "https://example.com/"), false);
  assert.equal(urlMatches("javascript:alert(1)", "https://example.com/"), false);
  assert.equal(urlMatches("https://example.com", "chrome://settings/"), false);
  assert.equal(urlMatches("chrome://settings", "chrome://settings/"), false);
  assert.equal(urlMatches("https://example.com", "data:text/html,example.com"), false);
  assert.equal(urlMatches("https://example.com", "file:///C:/example.com"), false);
  assert.equal(urlMatches("", "https://example.com/"), false);
  assert.equal(urlMatches("https://example.com", ""), false);
  assert.equal(urlMatches("https://exa mple.com", "https://example.com/"), false);
});

test("page non chiffrée et page web", () => {
  assert.ok(isInsecurePage("http://example.com/"));
  assert.equal(isInsecurePage("https://example.com/"), false);
  assert.equal(isInsecurePage("http://localhost:8080/"), false);
  assert.equal(isInsecurePage("http://127.0.0.1/"), false);
  assert.equal(webPage("chrome://newtab/"), null);
  assert.equal(webPage("https://example.com/a").hostname, "example.com");
});
