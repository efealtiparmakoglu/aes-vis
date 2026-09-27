import assert from "node:assert/strict";
import { test } from "node:test";

import {
  blockToHex,
  encrypt128,
  expandKey,
  gfMul,
  hexToBlock,
  SBOX,
  stateToString,
} from "../src/aes.ts";
import { renderTrace, selftest } from "../src/cli.ts";

test("gfMul matches the AES polynomial semantics", () => {
  assert.equal(gfMul(0x57, 0x83), 0xc1); // FIPS-197 §4.2 worked example
  assert.equal(gfMul(0x57, 0x13), 0xfe);
  assert.equal(gfMul(0x02, 0x87), 0x15); // overflow wraps via 0x1b
  assert.equal(gfMul(0, 0xff), 0);
  assert.equal(gfMul(1, 0xff), 0xff);
});

test("S-box matches published values and inverts through gfMul", () => {
  assert.equal(SBOX[0], 0x63);
  assert.equal(SBOX[0x01], 0x7c);
  assert.equal(SBOX[0x53], 0xed);
  assert.equal(SBOX[0xff], 0x16);
  // the affine image of the inverse maps 0x05 -> 0x6b in the standard table
  assert.equal(SBOX[0x05], 0x6b);
});

test("hex block conversion round trips", () => {
  const hex = "00112233445566778899aabbccddeeff";
  assert.equal(blockToHex(hexToBlock(hex)), hex);
  assert.equal(blockToHex(hexToBlock("00 11 22 33")), "00112233");
});

test("hex conversion rejects junk", () => {
  assert.throws(() => hexToBlock("zz"));
  assert.throws(() => hexToBlock("abc")); // odd length
});

test("key expansion first and last round keys (FIPS-197 C.1)", () => {
  const roundKeys = expandKey(hexToBlock("000102030405060708090a0b0c0d0e0f"));
  assert.equal(roundKeys.length, 11);
  assert.equal(blockToHex(roundKeys[0]), "000102030405060708090a0b0c0d0e0f");
  assert.equal(blockToHex(roundKeys[1]), "d6aa74fdd2af72fadaa678f1d6ab76fe");
  assert.equal(blockToHex(roundKeys[10]), "13111d7fe3944a17f307a78b4d2b30c5");
});

test("FIPS-197 Appendix B vector", () => {
  const out = encrypt128(
    hexToBlock("3243f6a8885a308d313198a2e0370734"),
    hexToBlock("2b7e151628aed2a6abf7158809cf4f3c"),
  );
  assert.equal(blockToHex(out), "3925841d02dc09fbdc118597196a0b32");
});

test("FIPS-197 Appendix C.1 vector", () => {
  const out = encrypt128(
    hexToBlock("00112233445566778899aabbccddeeff"),
    hexToBlock("000102030405060708090a0b0c0d0e0f"),
  );
  assert.equal(blockToHex(out), "69c4e0d86a7b0430d8cdb78070b4c55a");
});

test("all-zero vector", () => {
  const out = encrypt128(
    hexToBlock("00000000000000000000000000000000"),
    hexToBlock("00000000000000000000000000000000"),
  );
  assert.equal(blockToHex(out), "66e94bd4ef8a2c3b884cfa59ca342b2e");
});

test("encryption does not mutate its inputs", () => {
  const pt = hexToBlock("00112233445566778899aabbccddeeff");
  const key = hexToBlock("000102030405060708090a0b0c0d0e0f");
  const ptCopy = new Uint8Array(pt);
  encrypt128(pt, key);
  assert.deepEqual(pt, ptCopy);
});

test("trace records 11 states with distinct content", () => {
  const trace = {} as Parameters<typeof encrypt128>[2] & { states: unknown[] };
  encrypt128(
    hexToBlock("3243f6a8885a308d313198a2e0370734"),
    hexToBlock("2b7e151628aed2a6abf7158809cf4f3c"),
    trace,
  );
  assert.equal(trace.states.length, 11);
  const hexes = new Set(trace.states.map((s) => blockToHex(s.state)));
  assert.equal(hexes.size, 11); // every round changes the state
});

test("state matrix renders column-major like FIPS-197", () => {
  const block = hexToBlock("000102030405060708090a0b0c0d0e0f");
  // state[r + 4c]: row 0 = bytes 0,4,8,12 = 00 04 08 0c
  const rendered = stateToString(block);
  const rows = rendered.split("\n");
  assert.equal(rows[0], "00 04 08 0c");
  assert.equal(rows[1], "01 05 09 0d");
  assert.equal(rows[3], "03 07 0b 0f");
});

test("selftest passes all vectors", () => {
  const results = selftest();
  assert.ok(results.length >= 3);
  assert.ok(results.every((r) => r.pass), JSON.stringify(results));
});

test("renderTrace contains every round and the ciphertext", () => {
  const trace = {} as Parameters<typeof encrypt128>[2] & { states: unknown[] };
  encrypt128(
    hexToBlock("00112233445566778899aabbccddeeff"),
    hexToBlock("000102030405060708090a0b0c0d0e0f"),
    trace,
  );
  const text = renderTrace(trace);
  for (let round = 0; round <= 10; round++) {
    assert.ok(text.includes(`round ${round}`), `missing round ${round}`);
  }
  assert.ok(text.includes("ciphertext (hex): 69c4e0d86a7b0430d8cdb78070b4c55a"));
});
