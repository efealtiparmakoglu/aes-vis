/* aes.ts — AES-128 from first principles: GF(2^8) math, runtime-generated
 * S-box, key expansion, and a per-round trace for visualization. */

export type Block = Uint8Array; // always 16 bytes
export type RoundKey = Block;

const N_ROUNDS = 10;

/* --- GF(2^8) arithmetic with the AES polynomial 0x11b --- */

export function gfMul(a: number, b: number): number {
  let product = 0;
  for (let bit = 0; bit < 8; bit++) {
    if (b & 1) product ^= a;
    const high = a & 0x80;
    a = (a << 1) & 0xff;
    if (high) a ^= 0x1b;
    b >>= 1;
  }
  return product;
}

function gfInv(a: number): number {
  if (a === 0) return 0;
  // brute-force inverse: 255 multiplies max, only used at S-box build time
  for (let candidate = 1; candidate < 256; candidate++) {
    if (gfMul(a, candidate) === 1) return candidate;
  }
  throw new Error("no inverse");
}

/* --- S-box built at runtime: multiplicative inverse + affine transform --- */

function buildSbox(): Uint8Array {
  const sbox = new Uint8Array(256);
  for (let x = 0; x < 256; x++) {
    const inverse = gfInv(x);
    let transformed = 0;
    for (let bit = 0; bit < 8; bit++) {
      const b0 = (inverse >> bit) & 1;
      const b1 = (inverse >> ((bit + 4) % 8)) & 1;
      const b2 = (inverse >> ((bit + 5) % 8)) & 1;
      const b3 = (inverse >> ((bit + 6) % 8)) & 1;
      const b4 = (inverse >> ((bit + 7) % 8)) & 1;
      transformed |= (b0 ^ b1 ^ b2 ^ b3 ^ b4 ^ ((0x63 >> bit) & 1)) << bit;
    }
    sbox[x] = transformed;
  }
  return sbox;
}

export const SBOX = buildSbox();
export const INV_SBOX = (() => {
  const inv = new Uint8Array(256);
  for (let x = 0; x < 256; x++) inv[SBOX[x]] = x;
  return inv;
})();

/* --- state layout: column-major, state[r + 4c] per FIPS-197 --- */

export function stateToString(state: Block): string {
  const rows: string[] = [];
  for (let r = 0; r < 4; r++) {
    const row: string[] = [];
    for (let c = 0; c < 4; c++) row.push(state[r + 4 * c].toString(16).padStart(2, "0"));
    rows.push(row.join(" "));
  }
  return rows.join("\n");
}

export function blockToHex(block: Block): string {
  return Array.from(block, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBlock(hex: string): Block {
  const clean = hex.replace(/[\s:]/g, "");
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error(`invalid hex input: ${hex.slice(0, 40)}`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/* --- key expansion (FIPS-197 §5.2) --- */

const RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

export function expandKey(key: Block): RoundKey[] {
  if (key.length !== 16) throw new Error(`AES-128 key must be 16 bytes, got ${key.length}`);
  const words: number[] = new Array(44);
  for (let i = 0; i < 4; i++) {
    words[i] =
      (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
  }
  for (let i = 4; i < 44; i++) {
    let temp = words[i - 1];
    if (i % 4 === 0) {
      // RotWord + SubWord + Rcon
      const rotated = ((temp << 8) | (temp >>> 24)) >>> 0;
      const s = (SBOX[(rotated >>> 24) & 0xff] << 24) |
        (SBOX[(rotated >>> 16) & 0xff] << 16) |
        (SBOX[(rotated >>> 8) & 0xff] << 8) |
        SBOX[rotated & 0xff];
      temp = (s ^ (RCON[i / 4 - 1] << 24)) >>> 0; // >>> 0: keep 32-bit
    }
    words[i] = (words[i - 4] ^ temp) >>> 0; // >>> 0: force 32-bit unsigned
  }
  const roundKeys: RoundKey[] = [];
  for (let round = 0; round <= N_ROUNDS; round++) {
    const rk = new Uint8Array(16);
    for (let w = 0; w < 4; w++) {
      const word = words[round * 4 + w];
      rk[4 * w] = (word >>> 24) & 0xff;
      rk[4 * w + 1] = (word >>> 16) & 0xff;
      rk[4 * w + 2] = (word >>> 8) & 0xff;
      rk[4 * w + 3] = word & 0xff;
    }
    roundKeys.push(rk);
  }
  return roundKeys;
}

/* --- the four transformations --- */

function addRoundKey(state: Block, roundKey: Block): void {
  for (let i = 0; i < 16; i++) state[i] ^= roundKey[i];
}

function subBytes(state: Block): void {
  for (let i = 0; i < 16; i++) state[i] = SBOX[state[i]];
}

function shiftRows(state: Block): void {
  const copy = new Uint8Array(state);
  for (let r = 1; r < 4; r++) {
    for (let c = 0; c < 4; c++) {
      state[r + 4 * c] = copy[r + 4 * ((c + r) % 4)];
    }
  }
}

function mixColumns(state: Block): void {
  for (let c = 0; c < 4; c++) {
    const col = [state[4 * c], state[4 * c + 1], state[4 * c + 2], state[4 * c + 3]];
    state[4 * c + 0] = gfMul(col[0], 2) ^ gfMul(col[1], 3) ^ col[2] ^ col[3];
    state[4 * c + 1] = col[0] ^ gfMul(col[1], 2) ^ gfMul(col[2], 3) ^ col[3];
    state[4 * c + 2] = col[0] ^ col[1] ^ gfMul(col[2], 2) ^ gfMul(col[3], 3);
    state[4 * c + 3] = gfMul(col[0], 3) ^ col[1] ^ col[2] ^ gfMul(col[3], 2);
  }
}

/* --- encryption with per-round trace --- */

export interface EncryptionTrace {
  key: Block;
  plaintext: Block;
  ciphertext: Block;
  roundKeys: RoundKey[];
  states: { round: number; label: string; state: Block }[];
}

export function encrypt128(plaintext: Block, key: Block, trace?: EncryptionTrace): Block {
  const roundKeys = expandKey(key);
  const state = new Uint8Array(plaintext); // copy

  const record = (round: number, label: string) => {
    if (trace) trace.states.push({ round, label, state: new Uint8Array(state) });
  };

  if (trace) {
    trace.key = new Uint8Array(key);
    trace.plaintext = new Uint8Array(plaintext);
    trace.roundKeys = roundKeys;
    trace.states = [];
  }
  addRoundKey(state, roundKeys[0]);
  record(0, "round 0: initial AddRoundKey (round key 0)");

  for (let round = 1; round <= N_ROUNDS - 1; round++) {
    subBytes(state);
    shiftRows(state);
    mixColumns(state);
    addRoundKey(state, roundKeys[round]);
    record(round, `round ${round}: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey`);
  }

  subBytes(state);
  shiftRows(state);
  addRoundKey(state, roundKeys[N_ROUNDS]); // no MixColumns on the last round
  record(N_ROUNDS, `round 10 (final): SubBytes -> ShiftRows -> AddRoundKey`);

  if (trace) trace.ciphertext = new Uint8Array(state);
  return state;
}
