/* cli.ts — aes-vis command line: encrypt with round dump, state matrix
 * views, and a FIPS-197 known-answer self test. */
import {
  blockToHex,
  encrypt128,
  expandKey,
  hexToBlock,
  type EncryptionTrace,
  stateToString,
} from "./aes.ts";

export const VERSION = "1.0.0";

export function renderTrace(trace: EncryptionTrace): string {
  const lines: string[] = [];
  lines.push("key (hex):        " + blockToHex(trace.key));
  lines.push("plaintext (hex):  " + blockToHex(trace.plaintext));
  lines.push("");
  lines.push("round key 0:      " + blockToHex(trace.roundKeys[0]));
  lines.push("");
  for (const step of trace.states) {
    lines.push(`── ${step.label}`);
    lines.push(stateToString(step.state));
    if (step.round >= 0 && step.round < trace.roundKeys.length - 1) {
      lines.push("");
      lines.push(`next round key ${step.round + 1}:  ` + blockToHex(trace.roundKeys[step.round + 1]));
    }
    lines.push("");
  }
  lines.push("ciphertext (hex): " + blockToHex(trace.ciphertext));
  return lines.join("\n");
}

const usage = `aes-vis ${VERSION} — AES-128 step-by-step visualizer (educational)

usage:
  aes-vis encrypt --key <16-byte hex> --text <hex> [--dump]
  aes-vis selftest                       run FIPS-197 known-answer vectors
  aes-vis key-schedule --key <16-byte hex>
  aes-vis -h | --help

options:
  --key HEX       32 hex chars (16 bytes) round key material
  --text HEX      32 hex chars plaintext block
  --dump          print the state matrix after every transformation
  --json          trace as JSON instead of text

AES-128 encrypts 16-byte blocks with 16-byte keys. This tool exists to
SHOW the cipher working: eleven round keys, ten rounds, and the state
matrix after each stage.`;

export function selftest(): { name: string; pass: boolean }[] {
  // FIPS-197 Appendix B and Appendix C.1 vectors
  const vectors = [
    {
      name: "FIPS-197 Appendix B",
      key: "2b7e151628aed2a6abf7158809cf4f3c",
      plaintext: "3243f6a8885a308d313198a2e0370734",
      ciphertext: "3925841d02dc09fbdc118597196a0b32",
    },
    {
      name: "FIPS-197 Appendix C.1 (AES-128)",
      key: "000102030405060708090a0b0c0d0e0f",
      plaintext: "00112233445566778899aabbccddeeff",
      ciphertext: "69c4e0d86a7b0430d8cdb78070b4c55a",
    },
    {
      name: "all-zero block and key",
      key: "00000000000000000000000000000000",
      plaintext: "00000000000000000000000000000000",
      ciphertext: "66e94bd4ef8a2c3b884cfa59ca342b2e",
    },
  ];
  return vectors.map((v) => {
    const out = encrypt128(hexToBlock(v.plaintext), hexToBlock(v.key));
    return { name: v.name, pass: blockToHex(out) === v.ciphertext };
  });
}

export function run(args: string[]): number {
  if (args.length === 0 || args[0] === "-h" || args[0] == "--help") {
    console.error(usage);
    return 2;
  }
  const command = args[0];
  const rest = args.slice(1);

  const flag = (name: string): string | undefined => {
    const index = rest.indexOf(name);
    return index >= 0 ? rest[index + 1] : undefined;
  };

  try {
    if (command === "selftest") {
      const results = selftest();
      for (const r of results) {
        console.log(`${r.pass ? "PASS" : "FAIL"}  ${r.name}`);
      }
      return results.every((r) => r.pass) ? 0 : 1;
    }

    if (command === "encrypt") {
      const keyHex = flag("--key");
      const textHex = flag("--text");
      if (!keyHex || !textHex) {
        console.error("aes-vis: --key and --text are required for encrypt");
        return 2;
      }
      const trace: EncryptionTrace = {} as EncryptionTrace;
      const ciphertext = encrypt128(hexToBlock(textHex), hexToBlock(keyHex), trace);
      if (rest.includes("--dump")) {
        console.log(renderTrace(trace));
      } else {
        console.log(blockToHex(ciphertext));
      }
      return 0;
    }

    if (command === "key-schedule") {
      const keyHex = flag("--key");
      if (!keyHex) {
        console.error("aes-vis: --key is required for key-schedule");
        return 2;
      }
      const roundKeys = expandKey(hexToBlock(keyHex));
      roundKeys.forEach((rk, round) => {
        console.log(`round key ${round}: ${blockToHex(rk)}`);
      });
      return 0;
    }

    console.error(`aes-vis: unknown command '${command}'`);
    return 2;
  } catch (err) {
    console.error(`aes-vis: ${(err as Error).message}`);
    return 1;
  }
}

if (import.meta.main) {
  process.exit(run(process.argv.slice(2)));
}
