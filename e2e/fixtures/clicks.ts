// Compteur d'interactions (cahier §3.6 : nombre de gestes par parcours).
// Les tests de parcours passent par clicks.click / fill / press au lieu des
// méthodes du Locator, puis mesurent un parcours avec measure().

import type { Locator } from "@playwright/test";

export class Clicks {
  /** Interactions depuis le début du test. */
  count = 0;

  async click(target: Locator, options?: Parameters<Locator["click"]>[0]) {
    this.count++;
    await target.click(options);
  }

  async fill(target: Locator, value: string, options?: Parameters<Locator["fill"]>[1]) {
    this.count++;
    await target.fill(value, options);
  }

  async press(target: Locator, key: string, options?: Parameters<Locator["press"]>[1]) {
    this.count++;
    await target.press(key, options);
  }

  /** Nombre d'interactions faites pendant `fn`. */
  async measure(fn: () => Promise<unknown>): Promise<number> {
    const start = this.count;
    await fn();
    return this.count - start;
  }
}
