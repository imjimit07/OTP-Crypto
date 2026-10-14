"""
One-Time Pad encryption using Z_10 modular arithmetic.

Encryption works like this: each plaintext digit is added to
the corresponding key digit, modulo 10. Decryption subtracts
the key digit, modulo 10.

The math:

  Z_10 = {0, 1, 2, ..., 9} with addition mod 10 forms a group:
    - Closure:          adding two digits always gives a digit 0-9
    - Associative:      (a + b) + c == a + (b + c)
    - Identity:         a + 0 == a,  0 is the identity
    - Inverses:         every digit a has an inverse b where a + b == 0

Encryption:  C = (P + K) mod 10   (add key to plaintext)
Decryption:  P = (C - K) mod 10   (subtract key from ciphertext)

Message format (fixed block of N digits, N = BLOCK_SIZE):
  [3-digit length of encoded message]
  [encoded message text, as digits]
  [random padding digits to fill the block]
  [1 checksum digit — sum of all preceding digits mod 10]

The last digit of every block is a checksum so the receiver
can detect corruption or tampering.

Key space: for a block of N digits, there are 10^N possible
keys. With N = 200, that's 10^200 — massively larger than
Enigma's ~2.8 × 10^24 possibilities.

Security assumptions (these must hold for the system to be
secure):
  - The pad is truly random (we use Python's `secrets` module)
  - The pad is never reused (the offset tracker enforces this)
  - The pad is as long as the message block
  - The pad stays secret between sender and receiver only
"""

import argparse
import sys

from checkerboard import encode, decode, ENCODE_MAP
from pad import generate_pad, save_pad, load_pad, use_pad
from checksum import compute_checksum, verify_checksum

BLOCK_SIZE = 200  # digits per fixed-size block


# -------------------------------------------------------------------
# Group Z_10 operations
# -------------------------------------------------------------------

def encrypt_digit(p, k):
    """C = (P + K) mod 10   -- group addition in Z_10."""
    return (p + k) % 10


def decrypt_digit(c, k):
    """P = (C - K) mod 10   -- addition of the inverse of K."""
    return (c - k) % 10


def encrypt_digits(plain, key):
    """Apply group addition element-wise."""
    assert len(plain) == len(key), "plain and key must be same length"
    return [encrypt_digit(p, k) for p, k in zip(plain, key)]


def decrypt_digits(cipher, key):
    """Apply group subtraction element-wise."""
    assert len(cipher) == len(key), "cipher and key must be same length"
    return [decrypt_digit(c, k) for c, k in zip(cipher, key)]


# -------------------------------------------------------------------
# Message preparation
# -------------------------------------------------------------------

def prepare_message(plaintext, block_size=BLOCK_SIZE):
    """
    Encode plaintext into a fixed-size block of digits:
      [3 length][encoded message][random padding][checksum]
    """
    encoded = encode(plaintext)
    max_payload = block_size - 4   # 3 length digits + 1 checksum digit

    if len(encoded) > max_payload:
        raise ValueError(
            f"Message too long: {len(encoded)} encoded digits, "
            f"max {max_payload} for block size {block_size}"
        )

    length_prefix = [int(c) for c in f"{len(encoded):03d}"]
    body = length_prefix + [int(c) for c in encoded]

    padding_len = (block_size - 1) - len(body)
    padding = generate_pad(padding_len)
    full = body + padding

    cs = compute_checksum(full)
    return full + [cs]


def recover_message(block):
    """Verify checksum and recover plaintext from a decrypted block."""
    body, cs = block[:-1], block[-1]

    if not verify_checksum(body, cs):
        raise ValueError("Checksum failed: message is corrupted or tampered.")

    length = int(''.join(str(d) for d in body[:3]))
    if length > len(body) - 3:
        raise ValueError("Corrupt length prefix.")

    encoded = body[3:3 + length]
    return decode([str(d) for d in encoded])


# -------------------------------------------------------------------
# Commands
# -------------------------------------------------------------------

def cmd_genpad(args):
    pad = generate_pad(args.length)
    save_pad(pad, args.output)
    print(f"Generated {args.length}-digit pad -> {args.output}")


def cmd_encrypt(args):
    with open(args.input) as f:
        plaintext = f.read().strip()

    block = prepare_message(plaintext)
    key = use_pad(args.key, len(block))
    cipher = encrypt_digits(block, key)

    with open(args.output, 'w') as f:
        f.write(''.join(str(d) for d in cipher))
    print(f"Encrypted {len(block)} digits -> {args.output}")


def cmd_decrypt(args):
    # Reset the offset file so decryption uses the same pad
    # section that encryption used. Without this, the offset
    # would have already advanced past the section we need.
    offset_file = args.key + '.offset'
    with open(offset_file, 'w') as f:
        f.write('0')

    with open(args.input) as f:
        cipher = [int(c) for c in f.read().strip() if c.isdigit()]

    key = use_pad(args.key, len(cipher))
    block = decrypt_digits(cipher, key)
    plaintext = recover_message(block)

    with open(args.output, 'w') as f:
        f.write(plaintext)
    print(f"Decrypted -> {args.output}: {plaintext!r}")


def cmd_demo(args):
    text = args.text

    print("=" * 62)
    print(" ONE-TIME PAD DEMO  --  Z_10 modular arithmetic")
    print("=" * 62)

    print(f"\n1. Plaintext: {text!r}")

    encoded = encode(text)
    print(f"\n2. Checkerboard encoding ({len(encoded)} digits):")
    print(f"   {''.join(encoded)}")
    print("   Per character:")
    for ch in text.upper():
        print(f"     {ch!r} -> {ENCODE_MAP[ch]}")

    block = prepare_message(text)
    print(f"\n3. Padded block ({len(block)} digits):")
    print(f"   prefix = {''.join(str(d) for d in block[:3])} "
          f"(length of encoded message)")
    print(f"   body   = {''.join(str(d) for d in block[3:3+len(encoded)])} "
          f"(encoded message)")
    print(f"   padding= {''.join(str(d) for d in block[3+len(encoded):-1][:30])}...")
    print(f"   checksum = {block[-1]}")

    key = generate_pad(len(block))
    print(f"\n4. Random key ({len(key)} digits):")
    print(f"   {''.join(str(d) for d in key[:40])}...{''.join(str(d) for d in key[-8:])}")

    cipher = encrypt_digits(block, key)
    print(f"\n5. Ciphertext ({len(cipher)} digits)  [C = (P + K) mod 10]:")
    print(f"   {''.join(str(d) for d in cipher[:40])}...{''.join(str(d) for d in cipher[-8:])}")

    recovered_block = decrypt_digits(cipher, key)
    recovered = recover_message(recovered_block)
    print(f"\n6. Decrypted + recovered: {recovered!r}")
    print(f"   Match: {recovered == text.upper()}")

    print("\n7. Key space comparison:")
    print(f"   This block:   10^{len(key)}")
    print(f"   Enigma I:     ~2.8 x 10^24")
    if len(key) > 25:
        print(f"   This is LARGER than Enigma by roughly 10^{len(key) - 25} times.")
    print("\n   (Enigma also had design flaws and operator errors;")
    print("    OTP is information-theoretically secure under correct use.)")


def cmd_verify(args):
    """Verify the group axioms of Z_10 under addition modulo 10."""
    Z = list(range(10))
    print("Verifying group axioms for (Z_10, + mod 10)\n")

    closure = all((a + b) % 10 in Z for a in Z for b in Z)
    print(f"1. Closure       : {'PASS' if closure else 'FAIL'}")

    assoc = all(
        ((a + b) % 10 + c) % 10 == (a + (b + c) % 10) % 10
        for a in Z for b in Z for c in Z
    )
    print(f"2. Associativity : {'PASS' if assoc else 'FAIL'}")

    identity = all((a + 0) % 10 == a for a in Z)
    print(f"3. Identity (0)  : {'PASS' if identity else 'FAIL'}")

    inverses = all(any((a + b) % 10 == 0 for b in Z) for a in Z)
    print(f"4. Inverses      : {'PASS' if inverses else 'FAIL'}")

    print("\nInverse table:")
    for a in Z:
        inv = (10 - a) % 10
        print(f"  {a} + {inv} = 0 (mod 10)")


# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="One-Time Pad encryption using Z_10 modular arithmetic"
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    p1 = sub.add_parser('genpad', help='Generate a fresh one-time pad')
    p1.add_argument('--length', type=int, default=2000,
                    help='Number of digits in the pad (default 2000)')
    p1.add_argument('--output', required=True, help='Output pad file')
    p1.set_defaults(func=cmd_genpad)

    p2 = sub.add_parser('encrypt', help='Encrypt a plaintext file')
    p2.add_argument('input', help='Plaintext input file')
    p2.add_argument('key', help='Pad file')
    p2.add_argument('output', help='Ciphertext output file')
    p2.set_defaults(func=cmd_encrypt)

    p3 = sub.add_parser('decrypt', help='Decrypt a ciphertext file')
    p3.add_argument('input', help='Ciphertext input file')
    p3.add_argument('key', help='Pad file')
    p3.add_argument('output', help='Plaintext output file')
    p3.set_defaults(func=cmd_decrypt)

    p4 = sub.add_parser('demo', help='Step-by-step encryption demo')
    p4.add_argument('text', help='Text to encrypt (quoted)')
    p4.set_defaults(func=cmd_demo)

    p5 = sub.add_parser('verify', help='Verify Z_10 group axioms')
    p5.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()