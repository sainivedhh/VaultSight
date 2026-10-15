"""Utility functions for redacting sensitive values and matching contexts."""

import re
from typing import List, Optional


def redact_secret(raw_val: str, show_first: int = 2, show_last: int = 2, mask_char: str = "*") -> str:
    """Safely redact secret value, preserving only a minimal prefix/suffix when helpful, or total mask if short."""
    raw_val = raw_val.strip()
    length = len(raw_val)
    if length <= 4:
        return mask_char * length
    if length <= 8:
        return raw_val[:1] + (mask_char * (length - 2)) + raw_val[-1:]
    
    prefix = raw_val[:show_first]
    suffix = raw_val[-show_last:]
    masked_part = mask_char * min(12, length - show_first - show_last)
    return f"{prefix}{masked_part}{suffix}"


def has_context_keywords(text: str, match_start: int, match_end: int, keywords: List[str], window: int = 60) -> bool:
    """Check if any context keywords appear in a surrounding window of characters."""
    start = max(0, match_start - window)
    end = min(len(text), match_end + window)
    context_slice = text[start:end].lower()
    
    for kw in keywords:
        pattern = r"\b" + re.escape(kw.lower()) + r"\b"
        if re.search(pattern, context_slice):
            return True
    return False


def is_allowlisted_placeholder(value: str, allowlist: Optional[List[str]] = None) -> bool:
    """Detect if a value is an obvious placeholder, test string, or dummy value."""
    # If specific allowlist provided, check both exact match and specific prefixes/tokens
    target_allowlist = allowlist if allowlist else [
        "changeme", "placeholder", "dummy", "sample", "foobar", "qwerty",
        "123456789012", "000000000000", "111111111111", "xxxxxxxxxxxx",
        "akiatestexample", "your_api_key_here", "<password>", "bearer token",
        "null", "undefined", "fake_key"
    ]
    lower_val = value.lower().strip()
    clean_val = lower_val.replace("-", "").replace("_", "")

    for item in target_allowlist:
        clean_item = item.lower().replace("-", "").replace("_", "").strip()
        # Exact match or item is a clear substring with length >= 6
        if clean_val == clean_item:
            return True
        if len(clean_item) >= 6 and clean_item in clean_val:
            return True
    return False
