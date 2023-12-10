# AES — Pipelined RTL + Software Reference Model

Fully pipelined AES encrypt/decrypt core with a companion Python software model.
Both implement the same algorithm — the Python model can be used to generate golden
vectors and cross-check the hardware.



---

## Features

| | |
|---|---|
| Key sizes | 128 / 192 / 256 bit, selected by `KEY_W` parameter |
| Throughput | 1 block / cycle (fully pipelined) |
| Latency | Nr + 1 cycles — 11 / 13 / 15 for 128 / 192 / 256 |
| Decryption | Direct inverse cipher (FIPS 197 §5.3) |
| Language | Verilog-2001, no SystemVerilog |
| Simulator | Icarus Verilog (`iverilog`) |
| Vectors | FIPS 197 Appendix B, NIST CAVS |

---

## Repository layout

```
aes/
├── hardware/
│   ├── rtl/
│   │   ├── aes_encrypt.v      top-level encrypt pipeline
│   │   ├── aes_decrypt.v      top-level decrypt pipeline
│   │   ├── aes_round.v        one forward round (SubBytes+ShiftRows+MixColumns+ARK)
│   │   ├── aes_inv_round.v    one inverse round (InvShiftRows+InvSubBytes+ARK+InvMixColumns)
│   │   ├── aes_keyexp.v       combinational key schedule (128/192/256)
│   │   ├── aes_sbox.v         256-entry forward S-box
│   │   └── aes_inv_sbox.v     256-entry inverse S-box
│   └── sim/
│       └── aes_tb.v           FIPS 197 self-checking testbench
├── software/
│   └── aes.py                 Python reference model
├── Makefile
└── README.md
```

---

## Quick start

**RTL simulation**
```
make sim
```
Expected output:
```
PASS – AES-128/192/256 encrypt+decrypt all correct
```

**Python model**
```
make sw
```
Expected output:
```
AES-128  PASS
AES-192  PASS
AES-256  PASS

All tests passed.
```

**Clean build artefacts**
```
make clean
```

---

## Hardware architecture

Each pipeline has the same structure; decryption simply reverses the round-key
order and uses inverse transformations.

```
plaintext ──► [ARK rk0] ──► pipe[0]
                                │
                         [Round 1, rk1] ──► pipe[1]
                                │
                              ...
                                │
                        [Round Nr-1, rk(Nr-1)] ──► pipe[Nr-1]
                                │
                      [Final round, rkNr] ──► ciphertext
```

- All GF(2⁸) arithmetic is expressed as combinational `assign` chains (no
  Verilog functions, no tasks) so the design is synthesis-friendly.
- `KEY_W` is a single top-level parameter; `Nr` is derived from it via
  `localparam` so no structural changes are needed to switch key size.
- `valid_in` / `valid_out` handshake propagates through a parallel shift
  register (`vpipe`) that tracks data through the pipeline.

---

## Software model

`software/aes.py` implements the same algorithm in Python:

```python
from software.aes import encrypt, decrypt

key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
pt  = bytes.fromhex('3243f6a8885a308d313198a2e0370734')

ct  = encrypt(pt,  key)   # 3925841d02dc09fbdc118597196a0b32
rec = decrypt(ct,  key)   # 3243f6a8885a308d313198a2e0370734
```

The decryption path uses the **direct inverse cipher** (InvShiftRows →
InvSubBytes → AddRoundKey → InvMixColumns), matching the RTL's
`aes_inv_round` order, so intermediate round states agree between Python
and simulation waveforms.

---

## Test vectors

| Key size | Key | Plaintext | Ciphertext |
|---|---|---|---|
| 128 | `2b7e151628aed2a6abf7158809cf4f3c` | `3243f6a8885a308d313198a2e0370734` | `3925841d02dc09fbdc118597196a0b32` |
| 192 | `8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b` | `6bc1bee22e409f96e93d7e117393172a` | `bd334f1d6e45f25ff712a214571fa5cc` |
| 256 | `603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4` | `6bc1bee22e409f96e93d7e117393172a` | `f3eed1bdb5d2a03c064b5a7e3db181f8` |

---

## References

- FIPS 197 — *Announcing the Advanced Encryption Standard (AES)*, NIST, 2001
