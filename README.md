# aes-vis

**AES-128 step-by-step visualizer — GF(2^8) arithmetic, a runtime-generated S-box, the key schedule, and a state-matrix dump after every round. Educational. Zero dependencies (Node built-ins only).**

```
$ aes-vis encrypt --key 2b7e151628aed2a6abf7158809cf4f3c \
                   --text 3243f6a8885a308d313198a2e0370734 --dump
key (hex):        2b7e151628aed2a6abf7158809cf4f3c
plaintext (hex):  3243f6a8885a308d313198a2e0370734

round key 0:      2b7e151628aed2a6abf7158809cf4f3c

── round 0: initial AddRoundKey (round key 0)
19 a0 9a e9
3d f4 c6 f8
e3 e2 8d 48
be 2b 2a 08

next round key 1:  a0fafe1788542cb123a339392a6c7605

── round 1: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
a4 68 6b 02
9c 9f 5b 6a
7f 35 ea 50
f2 2b 43 49
...

ciphertext (hex): 3925841d02dc09fbdc118597196a0b32
```

Most explanations of AES show you a picture of the S-box and hand-wave the
rest. aes-vis actually *runs* the cipher and prints the 4×4 state matrix
after every transformation, so you can watch ShiftRows rotate row 1 and
MixColumns multiply by 2 and 3 in GF(2^8).

## Why aes-vis

- **Nothing is hardcoded except the standard itself.** The S-box is *built
  at runtime* — multiplicative inverse in GF(2^8) plus the FIPS-197 affine
  transform — and the tests check all 256 entries against the published
  table. The inverse S-box is derived from it.
- **GF(2^8) with the real polynomial.** `gfMul` implements the 0x11b
  reduction directly; the tests include the FIPS-197 §4.2 worked example
  (0x57 · 0x83 = 0xc1).
- **Key schedule shown, not asserted.** `key-schedule` prints all eleven
  round keys; the FIPS-197 Appendix A schedule (`a0fafe17 88542cb1 …`)
  falls out of the same code the encryption uses.
- **Round-by-round state dumps.** Every round's state is a 4×4 matrix in
  FIPS column-major layout, with the next round key alongside.
- **Known-answer self test.** `selftest` runs the FIPS-197 Appendix B and
  Appendix C.1 vectors plus an all-zero block, and exits non-zero on any
  mismatch — useful as a sanity check after any change.
- **Ciphertext cross-checked against `node:crypto`** in development, not
  by re-implementation: this is a teaching implementation, not a crypto
  library.

## Usage

```sh
aes-vis selftest                                # FIPS-197 known-answer vectors
aes-vis encrypt --key <32 hex> --text <32 hex>  # ciphertext hex
aes-vis encrypt --key <32 hex> --text <32 hex> --dump   # full round trace
aes-vis key-schedule --key <32 hex>             # 11 round keys
```

Exit codes: 0 ok, 1 self-test failure or bad input, 2 usage error.

AES-128 is a 16-byte-block, 16-byte-key cipher — one block per invocation
here. Padding, modes of operation and decryption are out of scope: this
tool shows the round function, not a usable crypto library.

## Development

```sh
node --test test/     # 13 tests, no network, sub-millisecond
```

## License

MIT — see [LICENSE](LICENSE).
