# One-Time Pad Encryption using Z_10 Modular Arithmetic

## Concept

Encryption is modeled as **group addition in Z₁₀ = {0, 1, …, 9}** under addition modulo 10.
A **straddling checkerboard** first compresses text into digits — common letters use one digit,
rare letters use two — giving an average of ~1.5 digits per letter (vs 2 for naive fixed-width).

## Math

| Operation | Formula |
|-----------|---------|
| **Encryption** | Cᵢ = (Pᵢ + Kᵢ) mod 10 |
| **Decryption** | Pᵢ = (Cᵢ − Kᵢ) mod 10 |

**(Z₁₀, + mod 10) is a group:**
- Closure, associativity
- Identity: 0
- Inverse of *a* is (10 − a) mod 10

```bash
python otp.py verify
```

Output:

```
Verifying group axioms for (Z_10, + mod 10)

1. Closure       : PASS
2. Associativity : PASS
3. Identity (0)  : PASS
4. Inverses      : PASS

Inverse table:
  0 + 0 = 0 (mod 10)
  1 + 9 = 0 (mod 10)
  2 + 8 = 0 (mod 10)
  3 + 7 = 0 (mod 10)
  4 + 6 = 0 (mod 10)
  5 + 5 = 0 (mod 10)
  6 + 4 = 0 (mod 10)
  7 + 3 = 0 (mod 10)
  8 + 2 = 0 (mod 10)
  9 + 1 = 0 (mod 10)
```

## Key space

For a block of N digits, the key space is **10ᴺ**.
With N = 200, key space = **10²⁰⁰**, versus Enigma I's ~2.8 × 10²⁴.

Under the OTP assumptions (truly random, never reused, as long as the message, kept secret),
the cipher is **information-theoretically secure**.

## How to run

<details><summary>Expand command table</summary>

| Step | Command | Description |
|------|---------|-------------|
| **1** | `python otp.py genpad --length 2000 --output alice_to_bob.pad` | Generate a pad (~2000 digits ≈ 10 messages) |
| **2** | `python otp.py encrypt msg.txt alice_to_bob.pad cipher.txt` | Encrypt a message |
| **3** | `python otp.py decrypt cipher.txt alice_to_bob.pad recovered.txt` | Decrypt (receiver uses same pad) |
| **4** | `python otp.py demo "Guten Tag"` | Step-by-step encryption demo |
| **5** | `python otp.py verify` | Verify Z₁₀ group axioms |

</details>

## Files

| File | Purpose |
|------|---------|
| `checkerboard.py` | Text ⇄ digits compression (straddling checkerboard) |
| `pad.py` | Secure pad generation and offset tracking |
| `checksum.py` | Encrypted checksum for tamper detection |
| `otp.py` | Main CLI and Z₁₀ group operations |
| `README.md` | This documentation |

## Security assumptions

- Pad is truly random (generated with `secrets`, not `random`)
- Pad is never reused (offset tracking enforces this)
- Pad is as long as the message block
- Pad is kept secret between sender and receiver only

## Limitations of this demo

- Only A-Z, space, and `.` are supported by the checkerboard
- One pad per direction (use a separate pad for A→B and B→A)
- Endpoint security (pen impressions, drafts, malware) is out of scope

## Demo: `python otp.py demo "Guten Tag"`

```bash
python otp.py demo "Guten Tag"
```

```
==============================================================
 ONE-TIME PAD DEMO  --  Z_10 modular arithmetic
==============================================================

1. Plaintext: 'Guten Tag'

2. Checkerboard encoding (13 digits):
   6223107681362
   Per character:
     'G' -> 62
     'U' -> 23
     'T' -> 1
     'E' -> 0
     'N' -> 7
     ' ' -> 68
     'T' -> 1
     'A' -> 3
     'G' -> 62

3. Padded block (200 digits):
   prefix = 013 (length of encoded message)
   body   = 6223107681362 (encoded message)
   padding= 049988745015535058385865217764...
   checksum = 1

4. Random key (200 digits):
   0770085151197102010724537899304168490888...03173768

5. Ciphertext (200 digits)  [C = (P + K) mod 10]:
   0806208258778464059602272804839116775643...28782679

6. Decrypted + recovered: 'GUTEN TAG'
   Match: True

7. Key space comparison:
   This block:   10^200
   Enigma I:     ~2.8 x 10^24
   This is LARGER than Enigma by roughly 10^175 times.

   (Enigma also had design flaws and operator errors;
    OTP is information-theoretically secure under correct use.)
```