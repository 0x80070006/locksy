// Tests de l'effacement du presse-papiers (web/js/ui/clipboard.js, utilisé
// par copySecret de ui/secret.js) : node --test web/tests/
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { decideClear, writeSecret, clearClipboardNow, setClipboardBackend } from "../js/ui/clipboard.js";

/** Faux presse-papiers : permission, lecture et écriture pilotables. */
function fakeClipboard({ permission = "granted", content = "", writable = true, readable = true } = {}) {
  const c = {
    content,
    writable,
    reads: 0,
    writes: [],
    async permission() {
      if (permission instanceof Error) throw permission;
      return permission;
    },
    async read() {
      c.reads++;
      if (!readable) throw new Error("NotAllowedError");
      return c.content;
    },
    async write(text) {
      if (!c.writable) throw new Error("Document is not focused.");
      c.writes.push(text);
      c.content = text;
    },
  };
  return c;
}

afterEach(() => setClipboardBackend(null));

test("rien en attente, ou échéance non atteinte : aucune action", async () => {
  const cb = fakeClipboard({ content: "s3cret" });
  assert.equal(await decideClear(null, 1000, cb), "none");
  assert.equal(await decideClear({ text: "s3cret", due: 2000 }, 1000, cb), "wait");
  assert.deepEqual(cb.writes, []);
});

test("contenu différent du secret : pas d'effacement", async () => {
  const cb = fakeClipboard({ content: "autre chose copié par l'utilisateur" });
  assert.equal(await decideClear({ text: "s3cret", due: 0 }, 1000, cb), "changed");
  assert.deepEqual(cb.writes, []);
  assert.equal(cb.content, "autre chose copié par l'utilisateur");
});

test("contenu encore égal au secret : effacé", async () => {
  const cb = fakeClipboard({ content: "s3cret" });
  assert.equal(await decideClear({ text: "s3cret", due: 0 }, 1000, cb), "cleared");
  assert.deepEqual(cb.writes, [""]);
});

test("permission refusée ou non accordée : effacement sans lecture", async () => {
  for (const permission of ["denied", "prompt"]) {
    const cb = fakeClipboard({ permission, content: "autre" });
    assert.equal(await decideClear({ text: "s3cret", due: 0 }, 1000, cb), "cleared");
    assert.equal(cb.reads, 0, "aucune lecture (donc aucune demande d'autorisation)");
    assert.deepEqual(cb.writes, [""]);
  }
});

test("permissions.query lève une exception (Firefox) : effacement sans condition", async () => {
  const cb = fakeClipboard({ permission: new TypeError("clipboard-read inconnu"), content: "autre" });
  assert.equal(await decideClear({ text: "s3cret", due: 0 }, 1000, cb), "cleared");
  assert.equal(cb.reads, 0);
});

test("lecture impossible malgré la permission : effacement par précaution", async () => {
  const cb = fakeClipboard({ readable: false, content: "s3cret" });
  assert.equal(await decideClear({ text: "s3cret", due: 0 }, 1000, cb), "cleared");
});

test("échec d'écriture (document sans focus) : nouvel essai demandé", async () => {
  const cb = fakeClipboard({ permission: "denied", writable: false, content: "s3cret" });
  assert.equal(await decideClear({ text: "s3cret", due: 0 }, 1000, cb), "retry");
  cb.writable = true;
  assert.equal(await decideClear({ text: "s3cret", due: 0 }, 1000, cb), "cleared");
});

test("copie puis clearClipboardNow : effacé tout de suite, une seule fois", async () => {
  const cb = fakeClipboard({ permission: "granted" });
  setClipboardBackend(cb);
  assert.equal(await writeSecret("s3cret", 30), true);
  assert.equal(cb.content, "s3cret");
  await clearClipboardNow();
  assert.equal(cb.content, "");
  await clearClipboardNow(); // plus rien en attente
  assert.deepEqual(cb.writes, ["s3cret", ""]);
});

test("clearClipboardNow n'écrase pas ce que l'utilisateur a copié ensuite", async () => {
  const cb = fakeClipboard({ permission: "granted" });
  setClipboardBackend(cb);
  await writeSecret("s3cret", 30);
  cb.content = "texte copié ailleurs";
  await clearClipboardNow();
  assert.equal(cb.content, "texte copié ailleurs");
});

test("écriture refusée au verrouillage : le secret reste en attente puis est effacé", async () => {
  const cb = fakeClipboard({ permission: "denied" });
  setClipboardBackend(cb);
  await writeSecret("s3cret", 30);
  cb.writable = false;
  await clearClipboardNow();
  assert.equal(cb.content, "s3cret");
  cb.writable = true;
  await clearClipboardNow(); // équivalent du nouvel essai au retour du focus
  assert.equal(cb.content, "");
});

test("copie refusée par le navigateur : writeSecret renvoie false", async () => {
  setClipboardBackend(fakeClipboard({ writable: false }));
  assert.equal(await writeSecret("s3cret", 30), false);
});

test("valeur non secrète (délai 0) : rien en attente, rien effacé au verrouillage", async () => {
  const cb = fakeClipboard({ permission: "denied" });
  setClipboardBackend(cb);
  await writeSecret("lien public", 0);
  await clearClipboardNow();
  assert.deepEqual(cb.writes, ["lien public"]);
});

test("échéance : effacement automatique sans action", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout", "Date"] });
  const cb = fakeClipboard({ permission: "denied" });
  setClipboardBackend(cb);
  await writeSecret("s3cret", 30);
  t.mock.timers.tick(29_000);
  await Promise.resolve();
  assert.equal(cb.content, "s3cret");
  t.mock.timers.tick(1_000);
  for (let i = 0; i < 5; i++) await Promise.resolve();
  assert.equal(cb.content, "");
});
