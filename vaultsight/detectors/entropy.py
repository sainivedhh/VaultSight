"""Shannon entropy calculation for high-entropy secret detection."""

import math
from collections import Counter


def calculate_shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string.
    
    H(X) = - sum(p(x) * log2(p(x)))
    Higher values (> 3.5 - 4.5 for alphanumeric strings of 20+ chars) indicate randomness/secrets.
    """
    if not data:
        return 0.0
    
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy


def is_high_entropy_secret(token: str, min_length: int = 16, threshold: float = 3.6) -> bool:
    """Determine whether a token qualifies as an unstructured high-entropy secret."""
    if len(token) < min_length:
        return False
    
    # Exclude common repeating sequences or non-alphanumeric walls
    if len(set(token)) <= 4:
        return False
        
    return calculate_shannon_entropy(token) >= threshold
