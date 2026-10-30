# Computer Network Security Lab

A responsive, local-first teaching workspace for the Computer Network Security Lab at Vidyalankar Institute of Technology (INFT).

## Start the lab

1. Install Node.js 18 or later.
2. From this directory, run `npm start`.
3. Open the exact local URL printed by `npm start` (if port 4173 is busy, the server automatically tries the next port).

The project has no external runtime dependencies. Experiment completion and the selected color theme are stored in the browser's local storage. The crypto API is served locally by `server.js`.

## What's included

- Thirteen interactive cryptography experiments, plus one reserved Kali Linux video placeholder.
- Additive, Caesar, monoalphabetic, substitution, repeating-key polyalphabetic, Playfair, Hill and Vigenère cipher workspaces with encryption, decryption and per-character, digraph or matrix-block calculations.
- Independent AES, DES, Double DES and Triple DES algorithm workspaces, plus a separate AES/DES modes-of-operation workspace for ECB, CBC, CFB, OFB and CTR.
- DES, two-key Double DES and EDE Triple DES demonstrations. DES keys are entered as exactly eight UTF-8 bytes.
- Character calculations, algorithm flow panels, reference notes, local progress, and dark/light themes inspired by the attached ivory, white and evergreen fintech dashboard reference.
- The Kali Linux section is a video placeholder only. There is no video-tutorial page or set of Kali practicals.

## Educational and implementation notes

- The block cipher implementation uses Node.js's OpenSSL-backed AES/DES block primitives. AES uses 10/12/14 rounds for 128/192/256-bit keys; DES uses 16 Feistel rounds per DES pass. The OpenSSL provider does not expose per-round intermediate states, so the interface describes the exact standard round sequence, reports actual AES block outputs, and shows the actual sequential DES results and keys used by 2DES/3DES rather than inventing intermediate values.
- AES keys must contain exactly 16, 24 or 32 UTF-8 bytes. Each DES key must contain exactly 8 UTF-8 bytes. The standalone cipher pages process padded blocks independently; the separate modes workspace implements each selected mode and requires a full-size IV / initial counter where applicable.
- ECB and nonce/IV reuse risks are explained in the modes workspace. DES and 3DES are legacy algorithms and are for instruction only.
- The Kali placeholder is where you can add your own video later.
