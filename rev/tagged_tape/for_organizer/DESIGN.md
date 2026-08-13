# tagged_tape Design

## Goal

This is a conventional hard reversing challenge for solvers who know ELF/IDA but may not know OCaml. It has two intended stages:

1. Recognize OCaml native values and recover a static array of algebraic-variant instructions.
2. Reverse a bijective byte transformation to recover the 64-byte hexadecimal flag payload.

No custom runtime, anti-debugging, effect handlers, GC puzzle, symbolic execution, or brute force is required.

## Data model

The verifier uses five non-constant variant constructors in declaration order:

| Runtime tag | Source constructor | Fields |
| --- | --- | --- |
| 0 | `Xor_at` | index, key |
| 1 | `Add_at` | index, key |
| 2 | `Rol_at` | index, amount |
| 3 | `Swap` | left, right |
| 4 | `Feistel` | left, right, key |

Every integer is a positive OCaml immediate encoded as `(n << 1) | 1`. Each constructor is a heap/static block whose header contains its field count and tag. The tape is a tag-0 array block containing pointers to 156 instruction blocks.

The capsule is a six-field record. Three tagged marker integers make the record discoverable without symbols; the other fields are the width, tape pointer, and OCaml string target. These markers contain no flag material.

## Transform

The generator builds 156 bijective operations from the private fixed seed:

- one operation touching each of 64 payload bytes;
- 32 Feistel operations coupling the two halves;
- 12 rounds containing all five operation kinds.

The target is the transformed 64-byte lowercase-hex payload. The public binary stores the target and tape but never stores the plaintext payload.

## Difficulty controls

- Non-PIE keeps IDA addresses and public-ELF parsing stable.
- General OCaml/runtime and `Correct.`/`Wrong.` anchors remain available.
- Source/debug/module symbols are removed from the participant binary.
- Only five constructor meanings need to be identified.
- The official solution is direct inversion, not SMT.
- All equal-length payloads execute the complete tape and comparison.

## Final release profile

- Participant binary SHA-256:
  `d123575638197b14ec60772dd49fc2259728858d79df88284a5d6df36faa7706`
- Organizer unstripped binary SHA-256:
  `5f8becee2276ab152573edbd15c0376e87ac032420b708cb4b6e0b24c38d535e`
- Format: x86-64, static, non-PIE (`ET_EXEC`), stripped
- `checksec`: Partial RELRO, no stack canary, NX enabled, no PIE; this verifier has no unsafe native input buffer
- `ldd`: not dynamically linked; the participant package needs no loader or shared library
- Build: OCaml 5.5.0, GCC 13.3.0, GNU binutils 2.42 in the pinned image documented by `src/TOOLCHAIN.md`
- Program entry logic: `0x402af0`
- Verifier: `0x402a70`, called at `0x402b9c`
- Operation dispatch: `0x402d80`, jump table at `0x526450`
- Program-data initialization: `0x4034a0`
- Target string data/header: `0x5a65c8` / `0x5a65c0`
- Tape fields/header: `0x5a6618` / `0x5a6610`
- `Correct.` / `Wrong.` / `KCTF{`: `0x5a5628` / `0x5a5618` / `0x5a5650`

Addresses are virtual addresses in the final non-PIE participant ELF. The participant binary does not
contain the organizer symbol names used to identify these routines during development.

## Release evidence

`src/verify.sh` performs two clean builds and requires byte-identical output, participant/organizer
binary parity, package hash validation, ELF protection/section checks, secret and semantic-name scans,
256 deterministic inverse-property cases, all 64 one-byte answer mutations, malformed-input cases,
an isolated public-binary-only solver run, and recovered-flag re-substitution. See `UNINTENDED.md` for
the threat-model ledger.
