"""
Checksum — quick integrity check for OTP ciphertext.

A one-time pad by itself doesn't have any way to tell if
ciphertext has been tampered with. If an attacker flips
a digit, the receiver will decrypt garbage without any
warning.

This module adds a simple checksum so the receiver can
detect corruption or malicious changes.

How it works:
- Add up all the digits in the message, then take mod 10.
- That single digit is the checksum. It's appended to the
  end of the encrypted block.
- On receipt, the same computation is done. If the computed
  checksum doesn't match the stored one, the message is
  rejected immediately.

It's not cryptographically strong (a determined attacker
could flip digits and adjust the checksum to match), but it
catches accidental corruption and casual tampering.
"""


def compute_checksum(digits):
    """Return the sum of all digits, modulo 10."""
    return sum(digits) % 10


def verify_checksum(digits, expected):
    """Return True if the checksum matches the expected value."""
    return compute_checksum(digits) == expected