"""Checksum algorithms for validating identity numbers and payment cards."""

# Verhoeff algorithm multiplication and permutation tables
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def validate_verhoeff(num_str: str) -> bool:
    """Validate a numeric string using the Verhoeff checksum algorithm.
    Used for 12-digit Indian Aadhaar numbers.
    """
    clean_num = "".join(ch for ch in num_str if ch.isdigit())
    if not clean_num:
        return False
    c = 0
    reversed_digits = [int(d) for d in reversed(clean_num)]
    for i, digit in enumerate(reversed_digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][digit]]
    return c == 0


def generate_verhoeff_checksum(num_str: str) -> int:
    """Generate the Verhoeff checksum digit for an 11-digit prefix to make a valid 12-digit number."""
    clean_num = "".join(ch for ch in num_str if ch.isdigit())
    c = 0
    reversed_digits = [int(d) for d in reversed(clean_num)]
    for i, digit in enumerate(reversed_digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][digit]]
    return _VERHOEFF_INV[c]


def validate_luhn(card_str: str) -> bool:
    """Validate a numeric string using the Luhn checksum (mod 10) algorithm.
    Used for payment card numbers (Visa, MasterCard, Amex, Discover, RuPay).
    """
    clean_digits = [int(d) for d in card_str if d.isdigit()]
    if len(clean_digits) < 13 or len(clean_digits) > 19:
        return False
    
    total = 0
    reverse_digits = clean_digits[::-1]
    for idx, digit in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = digit * 2
            total += doubled if doubled < 10 else (doubled - 9)
        else:
            total += digit
    return total % 10 == 0
