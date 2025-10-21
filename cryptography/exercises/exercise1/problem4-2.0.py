"""
Problem 4: Affine Cipher Brute Force Attack

Ciphertext from Alice to Bob:
RGMRQ ERQMZ MZXMD ENNZU QFD

Goal: Use brute force to find the plaintext and key.

Affine Cipher:
- Encryption: C = (a * P + b) mod 26
- Decryption: P = a^(-1) * (C - b) mod 26
- Key: (a, b) where gcd(a, 26) = 1

There are only 12 valid values for 'a' that are coprime with 26:
a ∈ {1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25}
And 26 possible values for 'b': {0, 1, 2, ..., 25}
Total key space: 12 * 26 = 312 keys
"""

import string
from collections import Counter


def gcd(a, b):
    """Calculate greatest common divisor."""
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a, m):
    """
    Find modular multiplicative inverse of a modulo m.
    Returns a^(-1) such that (a * a^(-1)) mod m = 1
    """
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def affine_decrypt(ciphertext, a, b):
    """
    Decrypt ciphertext using affine cipher with key (a, b).
    
    Formula: P = a^(-1) * (C - b) mod 26
    """
    # Find modular inverse of a
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return None
    
    plaintext = ""
    for char in ciphertext.upper():
        if char in string.ascii_uppercase:
            # Convert char to number (A=0, B=1, ..., Z=25)
            c = ord(char) - ord('A')
            # Decrypt: P = a^(-1) * (C - b) mod 26
            p = (a_inv * (c - b)) % 26
            # Convert back to letter
            plaintext += chr(p + ord('A'))
        else:
            plaintext += char
    
    return plaintext


def calculate_chi_squared(text):
    """
    Calculate chi-squared statistic to measure how "English-like" text is.
    Lower score = more likely to be English.
    """
    # Expected English letter frequencies (%)
    english_freq = {
        'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
        'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
        'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
        'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
        'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
        'Z': 0.074
    }
    
    # Remove non-letters
    text = ''.join(c for c in text.upper() if c in string.ascii_uppercase)
    
    if not text:
        return float('inf')
    
    # Count letter frequencies in text
    letter_count = Counter(text)
    text_length = len(text)
    
    # Calculate chi-squared statistic
    chi_squared = 0
    for letter in string.ascii_uppercase:
        observed = letter_count.get(letter, 0)
        expected = (english_freq[letter] / 100) * text_length
        if expected > 0:
            chi_squared += ((observed - expected) ** 2) / expected
    
    return chi_squared


def is_likely_english(text):
    """
    Simple heuristic to check if text looks like English.
    Checks for common words and patterns.
    """
    common_words = ['THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 
                    'CAN', 'HER', 'WAS', 'ONE', 'OUR', 'OUT', 'DAY', 'THIS',
                    'HAVE', 'FROM', 'THAT', 'WITH', 'THEY', 'BEEN', 'HAVE']
    
    text_upper = text.upper()
    
    # Count how many common words appear
    word_count = sum(1 for word in common_words if word in text_upper)
    
    # If we find multiple common words, it's likely English
    return word_count >= 2


def brute_force_affine(ciphertext):
    """
    Brute force all possible affine cipher keys.
    Returns list of (key, plaintext, chi_squared_score) tuples.
    """
    results = []
    
    # Valid values of 'a' (coprime with 26)
    valid_a = [a for a in range(1, 26) if gcd(a, 26) == 1]
    
    print(f"Valid values for 'a' (coprime with 26): {valid_a}")
    print(f"Total keys to try: {len(valid_a)} * 26 = {len(valid_a) * 26}\n")
    print("=" * 80)
    print("Attempting decryption with all possible keys...")
    print("=" * 80)
    
    for a in valid_a:
        for b in range(26):
            plaintext = affine_decrypt(ciphertext, a, b)
            if plaintext:
                # Calculate how "English-like" this plaintext is
                chi_squared = calculate_chi_squared(plaintext)
                results.append(((a, b), plaintext, chi_squared))
    
    # Sort by chi-squared score (lower is better)
    results.sort(key=lambda x: x[2])
    
    return results


def main():
    """Main function to solve Problem 4."""
    
    # The ciphertext from the exercise
    ciphertext = "RGMRQ ERQMZ MZXMD ENNZU QFD"
    
    print("=" * 80)
    print("AFFINE CIPHER BRUTE FORCE ATTACK")
    print("=" * 80)
    print(f"\nCiphertext: {ciphertext}")
    print(f"Length: {len(ciphertext.replace(' ', ''))} characters\n")
    
    # Remove spaces for analysis
    ciphertext_clean = ciphertext.replace(" ", "")
    
    # Brute force all keys
    results = brute_force_affine(ciphertext_clean)
    
    # Show top 10 most likely plaintexts
    print("\n" + "=" * 80)
    print("TOP 10 MOST LIKELY PLAINTEXTS (by chi-squared score)")
    print("=" * 80)
    print(f"{'Rank':<6} {'Key (a,b)':<12} {'Chi²':<10} {'Plaintext':<40}")
    print("-" * 80)
    
    for i, ((a, b), plaintext, chi_squared) in enumerate(results[:10], 1):
        # Add spaces every 5 characters for readability
        formatted_plaintext = ' '.join(plaintext[i:i+5] for i in range(0, len(plaintext), 5))
        print(f"{i:<6} ({a:2d},{b:2d}){' '*6} {chi_squared:<10.2f} {formatted_plaintext}")
    
    # Find results that look like English
    print("\n" + "=" * 80)
    print("PLAINTEXTS THAT LOOK LIKE ENGLISH")
    print("=" * 80)
    
    likely_results = [(key, pt, score) for key, pt, score in results if is_likely_english(pt)]
    
    if likely_results:
        for (a, b), plaintext, chi_squared in likely_results[:5]:
            formatted_plaintext = ' '.join(plaintext[i:i+5] for i in range(0, len(plaintext), 5))
            print(f"\nKey: (a={a}, b={b})")
            print(f"Chi-squared score: {chi_squared:.2f}")
            print(f"Plaintext: {formatted_plaintext}")
            print(f"Plaintext (no spaces): {plaintext}")
    else:
        print("No obvious English text found. Check the top results manually.")
    
    # Show the best result
    print("\n" + "=" * 80)
    print("BEST RESULT (lowest chi-squared)")
    print("=" * 80)
    (a, b), best_plaintext, best_score = results[0]
    formatted_best = ' '.join(best_plaintext[i:i+5] for i in range(0, len(best_plaintext), 5))
    print(f"\nKey: (a={a}, b={b})")
    print(f"Chi-squared score: {best_score:.2f}")
    print(f"Plaintext: {formatted_best}")
    print(f"Plaintext (no spaces): {best_plaintext}")
    
    # Verify decryption
    print("\n" + "=" * 80)
    print("ANSWER")
    print("=" * 80)
    print(f"✓ Found Key: a={a}, b={b}")
    print(f"✓ Plaintext: {best_plaintext}")
    print(f"✓ Formatted: {formatted_best}")


if __name__ == "__main__":
    main()