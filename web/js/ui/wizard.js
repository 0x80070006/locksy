// Assistant en étapes numérotées : « Étape 2 sur 4 », Retour, Continuer,
// Terminer ; chaque étape peut refuser d'avancer (validate) ; reprise à une
// étape donnée (current). Le titre de l'étape prend le focus à chaque passage.

import { t } from "../i18n.js";
import { clear, h, uid } from "./core.js";
import { button } from "./button.js";
import { focusSafely } from "./focus.js";

/**
 * wizard({ label, steps: [{ id, title, render, validate }], current, onFinish, onStep, finishLabel })
 *   -> { el, update(props), destroy(), go(id) }
 * render(conteneur, step) remplit l'étape ; validate() -> booléen (ou promesse) ;
 * onFinish() à la dernière étape validée ; onStep(id) à chaque changement.
 */
export function wizard({ label, steps = [], current, onFinish, onStep, finishLabel }) {
  let props = { steps, onFinish, onStep, finishLabel };
  let index = Math.max(0, steps.findIndex((s) => s.id === current));
  const headingId = uid("etape");
  const list = h("ol", { class: "c-wizard__steps", "aria-label": label });
  const body = h("section", { class: "l-stack", "aria-labelledby": headingId });
  const nav = h("div", { class: "l-cluster", "data-justify": "between" });
  const el = h("div", { class: "c-wizard" }, list, body, nav);

  const render = ({ focus = false } = {}) => {
    const all = props.steps;
    const step = all[index];
    if (!step) return;
    clear(list, all.map((s, i) => h("li", {
      class: "c-wizard__step", "aria-current": i === index ? "step" : undefined, "data-done": i < index ? "" : undefined,
    }, s.title, i < index ? h("span", { class: "u-sr-only" }, ` ${t("ui.wizard.done")}`) : null)));
    const content = h("div", { class: "l-stack" });
    const heading = h("h2", { id: headingId, tabindex: "-1" },
      h("span", { class: "u-sr-only" }, `${t("ui.wizard.position", { n: index + 1, total: all.length })} `), step.title);
    clear(body, heading, content);
    step.render?.(content, step);
    const last = index === all.length - 1;
    clear(nav,
      index > 0 ? button({ label: t("common.action.back"), icon: "arrow-left", onClick: () => go(index - 1, { focus: true }) }) : h("span", {}),
      button({
        label: last ? props.finishLabel || t("ui.wizard.finish") : t("common.action.continue"),
        variant: "primary", busyLabel: t("common.state.saving"),
        onClick: async () => {
          if (step.validate && !(await step.validate())) return;
          if (last) await props.onFinish?.();
          else go(index + 1, { focus: true });
        },
      }));
    if (focus) focusSafely(heading, { preventScroll: false });
  };

  const go = (i, opts) => {
    index = Math.min(props.steps.length - 1, Math.max(0, i));
    render(opts);
    props.onStep?.(props.steps[index].id);
  };

  render();
  return {
    el,
    go: (id) => go(props.steps.findIndex((s) => s.id === id), { focus: true }),
    update(next = {}) {
      props = { ...props, ...next, steps: next.steps || props.steps };
      if (next.current !== undefined) index = Math.max(0, props.steps.findIndex((s) => s.id === next.current));
      render();
    },
    destroy() {
      el.remove();
    },
  };
}
