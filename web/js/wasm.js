// Pont vers le noyau cryptographique Rust compilé en WebAssembly.
// Les clés restent dans la mémoire WebAssembly ; JavaScript ne reçoit que
// des numéros de poignée. Les tampons d'échange sont effacés après usage.

let exports = null;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class CryptoError extends Error {}

export async function loadCrypto(url = "/locksy.wasm") {
  if (exports) return;
  const imports = {
    locksy: {
      random_fill(ptr, len) {
        const view = new Uint8Array(exports.memory.buffer, ptr, len);
        for (let off = 0; off < len; off += 65536) {
          crypto.getRandomValues(view.subarray(off, Math.min(len, off + 65536)));
        }
      },
    },
  };
  const response = await fetch(url, { cache: "no-cache" });
  if (!response.ok) throw new Error("Module cryptographique introuvable.");
  const { instance } = await WebAssembly.instantiateStreaming(response, imports);
  exports = instance.exports;
}

export function call(op, args = {}) {
  if (!exports) throw new CryptoError("Module cryptographique non chargé.");
  const input = encoder.encode(JSON.stringify({ op, ...args }));
  const ptr = exports.locksy_alloc(input.length);
  new Uint8Array(exports.memory.buffer, ptr, input.length).set(input);
  input.fill(0);
  let packed;
  try {
    packed = exports.locksy_call(ptr, input.length);
  } finally {
    exports.locksy_free(ptr, input.length);
  }
  const outPtr = Number(BigInt.asUintN(64, packed) >> 32n);
  const outLen = Number(BigInt.asUintN(64, packed) & 0xffffffffn);
  const bytes = new Uint8Array(exports.memory.buffer, outPtr, outLen).slice();
  exports.locksy_free(outPtr, outLen);
  const text = decoder.decode(bytes);
  bytes.fill(0);
  const res = JSON.parse(text);
  if (!res.ok) throw new CryptoError(res.error);
  return res.result;
}

/** Laisse le navigateur afficher un indicateur avant un calcul long (Argon2id). */
export function nextFrame() {
  // Délai de secours : un onglet en arrière-plan ne rafraîchit plus l'écran.
  return new Promise((r) => {
    const done = () => r();
    requestAnimationFrame(() => setTimeout(done, 30));
    setTimeout(done, 120);
  });
}
