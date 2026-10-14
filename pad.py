"""
One-time pad — secure random digit generation and usage.

A pad is just a long list of random digits (0-9). It's the
heart of the whole system, so a few rules:

1. It must be *truly* random — we use Python's `secrets`
   module (not the regular `random`), which draws from
   the OS's cryptographic random source.

2. It must be at least as long as the message you encrypt
   with it. If you reuse digits, the whole system collapses.

3. Never reuse it. Ever. Each pad is for one message
   in one direction. If Alice sends Bob a message, they
   both burn that pad afterward.

4. Keep it secret. If someone finds your pad, all messages
   ever encoded with it are compromised.

The pad lives in a plain-text file. A companion `.offset`
file tracks how much of the pad has already been used, so
the system automatically hands out fresh digits for each
new message — and refuses to reuse old ones.
"""

import secrets


def generate_pad(length):
    """Generate a list of `length` cryptographically random digits."""
    return [secrets.randbelow(10) for _ in range(length)]


def save_pad(pad, filepath):
    """Save a pad to a text file (one digit per character)."""
    with open(filepath, 'w') as f:
        f.write(''.join(str(d) for d in pad))


def load_pad(filepath):
    """Load a pad from a text file."""
    with open(filepath) as f:
        content = f.read().strip()
    return [int(c) for c in content if c.isdigit()]


def use_pad(pad_file, n):
    """
    Consume the next `n` digits from the pad, advancing the offset.

    This enforces the one-time-use rule: once a section of pad has
    been used, the offset moves forward and it can never be reused.
    """
    offset_file = pad_file + '.offset'
    try:
        with open(offset_file) as f:
            offset = int(f.read().strip())
    except (FileNotFoundError, ValueError):
        offset = 0

    pad = load_pad(pad_file)
    if offset + n > len(pad):
        raise ValueError(
            f"Pad exhausted: need {n} digits at offset {offset}, "
            f"but pad only has {len(pad)} digits. Generate a new pad."
        )

    chunk = pad[offset:offset + n]
    with open(offset_file, 'w') as f:
        f.write(str(offset + n))
    return chunk