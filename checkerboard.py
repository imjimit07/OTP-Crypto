"""
Straddling checkerboard — turns text into digits (and back).

The grid layout:

    0   1   2   3   4   5   6   7   8   9
    E   T       A   O   I       N   S   H
2     R   D   L   U   C   M   F   W   Y   P
6     V   B   G   K   Q   J   X   Z   _   .

How it works:
- The most common letters (E, T, A, O, I, N, S, H) each have a
  single-digit code. This saves space.
- Every other letter needs two digits. The first digit is an
  "escape" — either 2 or 6 — that tells you the next digit is
  part of the letter's code.
- Digits 2 and 6 are the escape codes. After seeing a 2, the
  next digit picks which letter from the row-2 group. After 6,
  the next digit picks from the row-6 group.

Result: English text compresses to about 1.5 digits per letter
instead of 2 with a simple fixed-width code.

The maps are built at module import time.
"""

# Build encode and decode maps
ENCODE_MAP = {}
DECODE_MAP = {}

# --- Single-digit row (most common letters) ---
_single = {
    0: 'E', 1: 'T', 3: 'A', 4: 'O',
    5: 'I', 7: 'N', 8: 'S', 9: 'H',
}
for d, ch in _single.items():
    ENCODE_MAP[ch] = str(d)
    DECODE_MAP[str(d)] = ch

# --- Two-digit row starting with escape 2 ---
_row_2 = ['R', 'D', 'L', 'U', 'C', 'M', 'F', 'W', 'Y', 'P']
for i, ch in enumerate(_row_2):
    ENCODE_MAP[ch] = '2' + str(i)
    DECODE_MAP['2' + str(i)] = ch

# --- Two-digit row starting with escape 6 ---
_row_6 = ['V', 'B', 'G', 'K', 'Q', 'J', 'X', 'Z', ' ', '.']
for i, ch in enumerate(_row_6):
    ENCODE_MAP[ch] = '6' + str(i)
    DECODE_MAP['6' + str(i)] = ch


def encode(text):
    """Convert text to a list of digit characters."""
    text = text.upper()
    digits = []
    for ch in text:
        if ch not in ENCODE_MAP:
            raise ValueError(f"Cannot encode character: {ch!r}. "
                             f"Only A-Z, space, and '.' are supported.")
        digits.extend(ENCODE_MAP[ch])
    return digits


def decode(digits):
    """Convert a list of digit characters back to text."""
    result = []
    i = 0
    while i < len(digits):
        d = digits[i]
        if d in ('2', '6'):
            # Escape digit: read two digits together
            if i + 1 >= len(digits):
                raise ValueError("Dangling escape digit at end of input")
            code = d + digits[i + 1]
            if code not in DECODE_MAP:
                raise ValueError(f"Unknown two-digit code: {code}")
            result.append(DECODE_MAP[code])
            i += 2
        else:
            if d not in DECODE_MAP:
                raise ValueError(f"Unknown one-digit code: {d}")
            result.append(DECODE_MAP[d])
            i += 1
    return ''.join(result)