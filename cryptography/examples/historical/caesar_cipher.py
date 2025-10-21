"""
Caesar Cipher Implementation with Cryptanalysis Tools

Educational implementation demonstrating:
- Encryption and decryption
- Brute force attack
- Frequency analysis
- Interactive demonstrations

EDUCATIONAL PURPOSE ONLY - NOT FOR REAL SECURITY
"""

import string
from collections import Counter
from typing import Tuple, List

# English letter frequencies (approximate %)
ENGLISH_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
    'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
    'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
    'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
    'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07
}


def caesar_encrypt(plaintext: str, shift: int) -> str:
    """
    Encrypt plaintext using Caesar cipher.
    
    Args:
        plaintext: Text to encrypt (will be converted to uppercase)
        shift: Number of positions to shift (0-25)
        
    Returns:
        Encrypted ciphertext
        
    Example:
        >>> caesar_encrypt("HELLO", 3)
        'KHOOR'
    """
    result = []
    
    for char in plaintext.upper():
        if char in string.ascii_uppercase:
            # Shift character within alphabet
            shifted = (ord(char) - ord('A') + shift) % 26
            result.append(chr(shifted + ord('A')))
        else:
            # Keep non-alphabetic characters unchanged
            result.append(char)
    
    return ''.join(result)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """
    Decrypt ciphertext using Caesar cipher.
    
    Args:
        ciphertext: Text to decrypt
        shift: Number of positions used in encryption
        
    Returns:
        Decrypted plaintext
        
    Example:
        >>> caesar_decrypt("KHOOR", 3)
        'HELLO'
    """
    # Decryption is encryption with negative shift
    return caesar_encrypt(ciphertext, -shift)


def brute_force_caesar(ciphertext: str) -> List[Tuple[int, str]]:
    """
    Try all possible Caesar cipher shifts.
    
    Args:
        ciphertext: Encrypted text to crack
        
    Returns:
        List of (shift, decrypted_text) tuples for all 26 shifts
        
    Example:
        >>> brute_force_caesar("KHOOR")
        [(0, 'KHOOR'), (1, 'JGNNQ'), ..., (3, 'HELLO'), ...]
    """
    results = []
    
    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        results.append((shift, decrypted))
    
    return results


def calculate_chi_squared(text: str) -> float:
    """
    Calculate chi-squared statistic comparing text to English frequency.
    
    Lower chi-squared value indicates closer match to English.
    
    Args:
        text: Text to analyze
        
    Returns:
        Chi-squared value (lower is better match to English)
    """
    # Count letter frequencies
    text = ''.join(c for c in text.upper() if c in string.ascii_uppercase)
    if not text:
        return float('inf')
    
    observed = Counter(text)
    text_length = len(text)
    
    chi_squared = 0.0
    for letter in string.ascii_uppercase:
        observed_count = observed.get(letter, 0)
        expected_count = (ENGLISH_FREQ.get(letter, 0) / 100) * text_length
        
        if expected_count > 0:
            chi_squared += ((observed_count - expected_count) ** 2) / expected_count
    
    return chi_squared


def frequency_analysis_attack(ciphertext: str) -> Tuple[int, str]:
    """
    Break Caesar cipher using frequency analysis.
    
    Tries all shifts and returns the one that best matches English
    letter frequency using chi-squared test.
    
    Args:
        ciphertext: Encrypted text to crack
        
    Returns:
        Tuple of (most_likely_shift, decrypted_text)
        
    Example:
        >>> frequency_analysis_attack("KHOOR ZRUOG")
        (3, 'HELLO WORLD')
    """
    best_shift = 0
    best_score = float('inf')
    best_plaintext = ""
    
    for shift in range(26):
        plaintext = caesar_decrypt(ciphertext, shift)
        score = calculate_chi_squared(plaintext)
        
        if score < best_score:
            best_score = score
            best_shift = shift
            best_plaintext = plaintext
    
    return best_shift, best_plaintext


def analyze_text_frequency(text: str) -> None:
    """
    Display letter frequency analysis of text.
    
    Args:
        text: Text to analyze
    """
    text = ''.join(c for c in text.upper() if c in string.ascii_uppercase)
    total_letters = len(text)
    
    if total_letters == 0:
        print("No letters to analyze")
        return
    
    freq = Counter(text)
    
    print(f"\nFrequency Analysis ({total_letters} letters):")
    print("-" * 50)
    print(f"{'Letter':<8} {'Count':<8} {'Frequency':<12} {'Bar'}")
    print("-" * 50)
    
    # Sort by frequency
    for letter, count in freq.most_common():
        percentage = (count / total_letters) * 100
        bar = '█' * int(percentage)
        print(f"{letter:<8} {count:<8} {percentage:>5.2f}%       {bar}")


def demonstrate_caesar_cipher():
    """Interactive demonstration of Caesar cipher and attacks."""
    print("=" * 70)
    print("CAESAR CIPHER DEMONSTRATION")
    print("=" * 70)
    
    # Example 1: Basic encryption/decryption
    print("\n[EXAMPLE 1] Basic Encryption/Decryption")
    print("-" * 70)
    plaintext = "HELLO WORLD"
    shift = 3
    
    ciphertext = caesar_encrypt(plaintext, shift)
    decrypted = caesar_decrypt(ciphertext, shift)
    
    print(f"Plaintext:  {plaintext}")
    print(f"Shift:      {shift}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted:  {decrypted}")
    print(f"✓ Correct:  {plaintext == decrypted}")
    
    # Example 2: Brute force attack
    print("\n[EXAMPLE 2] Brute Force Attack")
    print("-" * 70)
    print(f"Trying all 26 possible shifts for: {ciphertext}\n")
    
    results = brute_force_caesar(ciphertext)
    for shift, text in results[:10]:  # Show first 10
        marker = " ← FOUND!" if text == plaintext else ""
        print(f"Shift {shift:2d}: {text}{marker}")
    print("... (remaining shifts omitted)")
    
    # Example 3: Frequency analysis
    print("\n[EXAMPLE 3] Frequency Analysis Attack")
    print("-" * 70)
    longer_text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    encrypted = caesar_encrypt(longer_text, 7)
    
    print(f"Original:  {longer_text}")
    print(f"Encrypted: {encrypted}")
    
    guessed_shift, guessed_text = frequency_analysis_attack(encrypted)
    print(f"\nFrequency analysis result:")
    print(f"Guessed shift: {guessed_shift}")
    print(f"Decrypted:     {guessed_text}")
    print(f"✓ Correct:     {guessed_text == longer_text}")
    
    # Example 4: Letter frequency comparison
    print("\n[EXAMPLE 4] Letter Frequency Analysis")
    print("-" * 70)
    analyze_text_frequency(longer_text)
    
    # Example 5: Security demonstration
    print("\n[EXAMPLE 5] Why Caesar Cipher is Insecure")
    print("-" * 70)
    print("Reasons Caesar cipher should NEVER be used for real security:")
    print("1. Only 26 possible keys (brute force takes < 1 second)")
    print("2. Frequency analysis reveals patterns")
    print("3. Known plaintext attack trivial (one letter reveals shift)")
    print("4. No protection against modern cryptanalysis")
    print("\n✓ Use modern encryption (AES-256) instead!")


if __name__ == "__main__":
    # Run demonstration
    demonstrate_caesar_cipher()
    
    # Interactive mode
    print("\n" + "=" * 70)
    print("INTERACTIVE MODE")
    print("=" * 70)
    
    while True:
        print("\nOptions:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Break Caesar cipher (brute force)")
        print("4. Break Caesar cipher (frequency analysis)")
        print("5. Exit")
        
        choice = input("\nChoose option (1-5): ").strip()
        
        if choice == '1':
            text = input("Enter plaintext: ").strip()
            shift = int(input("Enter shift (0-25): "))
            result = caesar_encrypt(text, shift)
            print(f"Encrypted: {result}")
            
        elif choice == '2':
            text = input("Enter ciphertext: ").strip()
            shift = int(input("Enter shift (0-25): "))
            result = caesar_decrypt(text, shift)
            print(f"Decrypted: {result}")
            
        elif choice == '3':
            text = input("Enter ciphertext to break: ").strip()
            print("\nTrying all shifts:")
            results = brute_force_caesar(text)
            for shift, plaintext in results:
                print(f"Shift {shift:2d}: {plaintext}")
            
        elif choice == '4':
            text = input("Enter ciphertext to break: ").strip()
            shift, plaintext = frequency_analysis_attack(text)
            print(f"\nMost likely shift: {shift}")
            print(f"Decrypted text: {plaintext}")
            
        elif choice == '5':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")
