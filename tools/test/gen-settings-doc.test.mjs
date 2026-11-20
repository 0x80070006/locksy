// Tests du générateur de la documentation des réglages (tools/gen-settings-doc.mjs).
//   node --test tools/test
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

import {
  parseRegistry, renderDoc, tokenize, frNumber, cell, slug, build, ROOT, DEFAULT_REGISTRY,
} from "../gen-settings-doc.mjs";

const GEN = join(ROOT, "tools", "gen-settings-doc.mjs");

/** Extrait de registre : entrée multiligne, chaque type, chaque modificateur. */
const EXTRAIT = `
pub const DEFAULT_ACCENT: &str = "#1b6b5f";
pub enum Section {
    Login,
    Sessions,
    Branding,
}
const DURATIONS_MIN: &[i64] = &[5, 10, 1_440];
use Def::{Bool as B, Int as I, List as L, Str as S};
pub static REGISTRY: &[SettingDef] = &[
    // ------------------------------------------- Sessions (déclarée avant Login)
    s("client.autolock_minutes", Sec::Sessions, 30, int(1, 1440, Unit::Minutes), I(10))
        .clients()
        .modal(Mode::Default)
        .admin_max(120)
        .down()
        .pre(DURATIONS_MIN)
        .syn(&["verrou", "veille"]),
    s("session.idle_minutes", Sec::Sessions, 10, int(5, 1440, Unit::Minutes), I(60)).down().v1().pre(&[0, 30, 1_440]),
    s(
        "directory.deprovision",
        Sec::Login,
        70,
        Kind::Enum(&["disable", "disable_then_delete"]),
        S("disable_then_delete"),
    )
    .up(),
    s("twofa.required", Sec::Login, 10, Kind::Bool, B(false)).owner().up(),
    s("twofa.required_roles", Sec::Login, 20, Kind::Roles, L(&[])).owner().adv(),
    s("access.allowed_email_domains", Sec::Login, 30, Kind::Domains, L(&["exemple.fr"])),
    s("access.ip_allowlist", Sec::Login, 40, Kind::Cidrs, L(&[])),
    s("master_password.banned_words", Sec::Login, 50, Kind::Words { max: 500 }, L(&[])).public(),
    s("mail.smtp.password", Sec::Login, 60, Kind::Secret, S("")),
    s("mail.from", Sec::Login, 80, Kind::Email, S("")),
    s("legal.notice_url", Sec::Branding, 10, Kind::Url { https_only: true }, S("")).public(),
    s("branding.logo", Sec::Branding, 20, Kind::Image { max_bytes: 262_144 }, S("")).public(),
    s("branding.accent_color", Sec::Branding, 30, Kind::Color, S(DEFAULT_ACCENT)).public().checked(check_accent),
    s("branding.org_name", Sec::Branding, 40, text(60), S("")).public(),
    s("legal.charter_text", Sec::Branding, 50, multiline(20_000), S("")).clients(),
    s("attachment.max_file_mib", Sec::Branding, 60, int(1, 15, Unit::Mib), I(10)).capped("LOCKSY_MAX_ATTACHMENT_MIB"),
    s("session.max_per_user", Sec::Login, 90, int(0, 100, Unit::Count), I(0)).down(),
];
const ZERO_IS_UNLIMITED: &[&str] = &["session.max_per_user"];
`;

/** Catalogue minimal : un libellé par clé et par section. */
function catalogFor(defs, omit = []) {
  const cat = {
    "settings.mode.free": "Libres",
    "settings.mode.default": "Par défaut",
    "settings.mode.enforced": "Imposé",
    "settings.section.login.label": "Sécurité de connexion",
    "settings.section.sessions.label": "Sessions et verrouillage",
    "settings.section.branding.label": "Apparence et textes",
    "settings.client.autolock_minutes.unit": "min",
    "settings.client.autolock_minutes.help": "Délai sans utilisation.",
    "settings.directory.deprovision.value.disable": "Désactiver",
  };
  for (const d of defs) if (!omit.includes(d.key)) cat[`settings.${d.key}.label`] = `Libellé ${d.key}`;
  return cat;
}

function tempDir(t) {
  const dir = mkdtempSync(join(tmpdir(), "locksy-reglages-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

const runGen = (args) => spawnSync(process.execPath, [GEN, ...args], { encoding: "utf8" });

describe("analyse du registre", () => {
  const parsed = parseRegistry(EXTRAIT);
  const byKey = Object.fromEntries(parsed.defs.map((d) => [d.key, d]));

  test("toutes les entrées de l'extrait sont lues, sans erreur", () => {
    assert.deepEqual(parsed.errors, []);
    assert.equal(parsed.defs.length, (EXTRAIT.match(/(?<![A-Za-z0-9_])s\(\s*"/g) || []).length);
    assert.deepEqual(parsed.sections, ["login", "sessions", "branding"]);
    assert.deepEqual(parsed.zeroUnlimited, ["session.max_per_user"]);
  });

  test("entrée multiligne et type énuméré", () => {
    const d = byKey["directory.deprovision"];
    assert.equal(d.section, "login");
    assert.equal(d.order, 70);
    assert.deepEqual(d.kind, { type: "enum", values: ["disable", "disable_then_delete"] });
    assert.equal(d.default, "disable_then_delete");
    assert.equal(d.safer, "higher");
  });

  test("chaque type est reconnu", () => {
    const types = Object.fromEntries(parsed.defs.map((d) => [d.key, d.kind]));
    assert.deepEqual(types["client.autolock_minutes"], { type: "int", min: 1, max: 1440, unit: "minutes" });
    assert.deepEqual(types["twofa.required"], { type: "bool" });
    assert.deepEqual(types["twofa.required_roles"], { type: "roles" });
    assert.deepEqual(types["access.allowed_email_domains"], { type: "domains" });
    assert.deepEqual(types["access.ip_allowlist"], { type: "cidrs" });
    assert.deepEqual(types["master_password.banned_words"], { type: "words", max: 500 });
    assert.deepEqual(types["mail.smtp.password"], { type: "secret" });
    assert.deepEqual(types["mail.from"], { type: "email" });
    assert.deepEqual(types["legal.notice_url"], { type: "url", httpsOnly: true });
    assert.deepEqual(types["branding.logo"], { type: "image", maxBytes: 262_144 });
    assert.deepEqual(types["branding.accent_color"], { type: "color" });
    assert.deepEqual(types["branding.org_name"], { type: "text", maxLen: 60, multiline: false });
    assert.deepEqual(types["legal.charter_text"], { type: "text", maxLen: 20_000, multiline: true });
  });

  test("valeurs par défaut, constantes et tables résolues", () => {
    assert.equal(byKey["twofa.required"].default, false);
    assert.equal(byKey["client.autolock_minutes"].default, 10);
    assert.deepEqual(byKey["access.allowed_email_domains"].default, ["exemple.fr"]);
    assert.equal(byKey["branding.accent_color"].default, "#1b6b5f");
    assert.deepEqual(byKey["client.autolock_minutes"].presets, [5, 10, 1440]);
    assert.deepEqual(byKey["session.idle_minutes"].presets, [0, 30, 1440]);
  });

  test("chaque modificateur est appliqué", () => {
    const a = byKey["client.autolock_minutes"];
    assert.equal(a.client, true);
    assert.equal(a.scope, "policy");
    assert.equal(a.modes, true);
    assert.equal(a.defaultMode, "default");
    assert.equal(a.adminMax, 120);
    assert.equal(a.safer, "lower");
    assert.deepEqual(a.synonyms, ["verrou", "veille"]);
    assert.equal(byKey["twofa.required"].ownerOnly, true);
    assert.equal(byKey["twofa.required_roles"].advanced, true);
    assert.equal(byKey["legal.notice_url"].scope, "public");
    assert.equal(byKey["session.idle_minutes"].since, 1);
    assert.equal(byKey["branding.org_name"].since, 2);
    assert.equal(byKey["branding.accent_color"].check, "check_accent");
    assert.equal(byKey["attachment.max_file_mib"].hostCap, "LOCKSY_MAX_ATTACHMENT_MIB");
  });

  test("clé en double : erreur", () => {
    const src = EXTRAIT.replace("s(\"mail.from\"", "s(\"mail.smtp.password\"");
    assert.ok(parseRegistry(src).errors.some((e) => e.includes("clé en double : mail.smtp.password")));
  });

  test("modificateur inconnu : erreur", () => {
    const src = EXTRAIT.replace(".owner().adv()", ".owner().cache()");
    assert.ok(parseRegistry(src).errors.some((e) => e.includes("modificateur inconnu .cache()")));
  });

  test("entrée illisible : l'autocontrôle du nombre d'entrées échoue", () => {
    const src = EXTRAIT.replace("s(\"mail.from\", Sec::Login, 80, Kind::Email, S(\"\")),", "s(\"mail.from\", Sec::Login, 80, Kind::Email, S(\"\")) + 1,");
    assert.ok(parseRegistry(src).errors.length > 0);
  });

  test("type ou section inconnus : erreur", () => {
    assert.ok(parseRegistry(EXTRAIT.replace("Kind::Email,", "Kind::Phone,")).errors.some((e) => e.includes("type inconnu")));
    assert.ok(parseRegistry(EXTRAIT.replace("Sec::Login, 80", "Sec::Ailleurs, 80")).errors.some((e) => e.includes("section inconnue")));
  });

  test("bloc absent : erreur claire", () => {
    assert.match(parseRegistry("fn main() {}").errors[0], /bloc introuvable/);
  });

  test("les commentaires et les chaînes ne gênent pas la lecture", () => {
    const toks = tokenize("s(\"a // b\", 1_000) // fin\n/* bloc */ x::y");
    assert.deepEqual(toks.map((t) => t.v), ["s", "(", "a // b", ",", 1000, ")", "x", "::", "y"]);
  });
});

describe("rendu Markdown", () => {
  const parsed = parseRegistry(EXTRAIT);

  test("une ligne de tableau par clé, dans l'ordre des sections puis de l'ordre d'affichage", () => {
    const { text, errors } = renderDoc(parsed, catalogFor(parsed.defs));
    assert.deepEqual(errors, []);
    const rows = text.split("\n").filter((l) => /^\| .* \| `[a-z0-9_.]+` \|/.test(l));
    const keys = rows.map((l) => /\| `([a-z0-9_.]+)` \|/.exec(l)[1]);
    assert.equal(keys.length, parsed.defs.length);
    assert.deepEqual(keys.slice(0, 3), ["twofa.required", "twofa.required_roles", "access.allowed_email_domains"]);
    assert.ok(keys.indexOf("session.max_per_user") < keys.indexOf("session.idle_minutes"), "Login avant Sessions");
    assert.ok(keys.indexOf("session.idle_minutes") < keys.indexOf("client.autolock_minutes"), "ordre 10 avant 30");
  });

  test("contenu des colonnes : bornes, défaut, modes, diffusion, plafond, sens sûr", () => {
    const { text } = renderDoc(parsed, catalogFor(parsed.defs));
    const row = (key) => text.split("\n").find((l) => l.includes(`| \`${key}\` |`));
    assert.match(row("client.autolock_minutes"), /1 à 1 440 min \| 10 min \| Libres, Par défaut, Imposé ; mode initial : Par défaut ; choix des utilisateurs limité à 120 min \(2 heures\) au plus \| oui \| non \| — \| plus bas \|/);
    assert.match(row("twofa.required"), /\| oui ou non \| non \| — \| non \| oui \| — \| activé \|/);
    assert.match(row("attachment.max_file_mib"), /`LOCKSY_MAX_ATTACHMENT_MIB`/);
    assert.match(row("session.max_per_user"), /0 à 100 ; 0 = sans limite \| 0 \(sans limite\)/);
    assert.match(row("directory.deprovision"), /« Désactiver » \(`disable`\), `disable_then_delete`/);
    assert.match(row("legal.notice_url"), /\| page de connexion \|/);
    assert.match(row("twofa.required_roles"), /Libellé twofa\.required_roles \(avancé\)/);
    assert.match(text, /- \*\*Libellé client\.autolock_minutes\*\* : Délai sans utilisation\. Valeurs proposées : 5 min, 10 min, 1 440 min \(1 jour\)\./);
  });

  test("clé sans libellé : erreur", () => {
    const { errors } = renderDoc(parsed, catalogFor(parsed.defs, ["mail.from"]));
    assert.deepEqual(errors, ["libellé absent : settings.mail.from.label (design/i18n/fr/settings.json)"]);
  });

  test("sortie déterministe, indépendante de l'ordre du source", () => {
    const cat = catalogFor(parsed.defs);
    const a = renderDoc(parsed, cat).text;
    const b = renderDoc(parseRegistry(EXTRAIT), cat).text;
    const shuffled = { ...parsed, defs: [...parsed.defs].reverse() };
    assert.equal(a, b);
    assert.equal(renderDoc(shuffled, cat).text, a);
    assert.doesNotMatch(a, /20\d\d-\d\d-\d\d/, "aucune date");
  });

  test("outils de mise en forme", () => {
    assert.equal(frNumber(43200), "43 200");
    assert.equal(frNumber(-5), "-5");
    assert.equal(cell("a|b\nc"), "a\\|b c");
    assert.equal(slug("Connexion d'entreprise"), "connexion-dentreprise");
    assert.equal(slug("Sécurité de connexion"), "sécurité-de-connexion");
  });
});

describe("registre réel du dépôt", () => {
  test("chaque clé du registre apparaît exactement une fois dans la sortie", () => {
    const source = readFileSync(DEFAULT_REGISTRY, "utf8");
    const block = source.slice(source.indexOf("pub static REGISTRY"), source.indexOf("const ZERO_IS_UNLIMITED"));
    const expected = [...block.matchAll(/(?<![A-Za-z0-9_])s\(\s*"([^"]+)"/g)].map((m) => m[1]);
    assert.ok(expected.length > 0);
    const { text, count, errors } = build();
    assert.deepEqual(errors, []);
    assert.equal(count, expected.length);
    for (const key of expected) {
      const hits = text.split(`\`${key}\``).length - 1;
      assert.equal(hits, 1, `${key} : ${hits} occurrence(s)`);
      assert.equal(text.split("\n").filter((l) => l.startsWith("| ") && l.includes(`| \`${key}\` |`)).length, 1, `${key} : ligne de tableau`);
    }
  });

  test("ligne de commande : écriture, --check à jour puis périmé, option inconnue", (t) => {
    const dir = tempDir(t);
    const out = join(dir, "Reglages.md");
    const write = runGen(["--out", out]);
    assert.equal(write.status, 0, write.stderr);
    assert.equal(runGen(["--check", "--out", out]).status, 0);
    writeFileSync(out, `${readFileSync(out, "utf8")}\nligne ajoutée à la main\n`);
    const stale = runGen(["--check", "--out", out]);
    assert.equal(stale.status, 1);
    assert.match(stale.stderr, /n'est pas à jour/);
    assert.equal(runGen(["--inconnue"]).status, 1);
  });

  test("ligne de commande : un libellé absent empêche toute écriture", (t) => {
    const dir = tempDir(t);
    const catalog = JSON.parse(readFileSync(join(ROOT, "design", "i18n", "fr.gen.json"), "utf8"));
    delete catalog["settings.twofa.required.label"];
    const cat = join(dir, "fr.gen.json");
    writeFileSync(cat, JSON.stringify(catalog));
    const out = join(dir, "Reglages.md");
    const r = runGen(["--catalog", cat, "--out", out]);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /libellé absent : settings\.twofa\.required\.label/);
    assert.throws(() => readFileSync(out));
  });
});
