"""
Vigenère Cipher Implementation with Cryptanalysis Tools

Educational implementation demonstrating:
- Encryption and decryption
- Kasiski examination (finding keyword length)
- Friedman test (Index of Coincidence)
- Breaking Vigenère cipher
- Interactive demonstrations

EDUCATIONAL PURPOSE ONLY - NOT FOR REAL SECURITY
"""

import string
from collections import Counter
from typing import List, Tuple
import math

# English Index of Coincidence (IC)
ENGLISH_IC = 0.0667


def vigenere_encrypt(plaintext: str, keyword: str) -> str:
    """
    Encrypt plaintext using Vigenère cipher.
    
    Args:
        plaintext: Text to encrypt
        keyword: Encryption keyword (letters only)
        
    Returns:
        Encrypted ciphertext
        
    Example:
        >>> vigenere_encrypt("HELLO WORLD", "KEY")
        'RIJVS UYVJN'
    """
    result = []
    keyword = keyword.upper()
    keyword_index = 0
    
    for char in plaintext.upper():
        if char in string.ascii_uppercase:
            # Get shift from current keyword letter
            shift = ord(keyword[keyword_index % len(keyword)]) - ord('A')
            # Encrypt character
            encrypted = (ord(char) - ord('A') + shift) % 26
            result.append(chr(encrypted + ord('A')))
            keyword_index += 1
        else:
            # Keep non-alphabetic characters unchanged
            result.append(char)
    
    return ''.join(result)


def vigenere_decrypt(ciphertext: str, keyword: str) -> str:
    """
    Decrypt ciphertext using Vigenère cipher.
    
    Args:
        ciphertext: Text to decrypt
        keyword: Decryption keyword (same as encryption)
        
    Returns:
        Decrypted plaintext
        
    Example:
        >>> vigenere_decrypt("RIJVS UYVJN", "KEY")
        'HELLO WORLD'
    """
    result = []
    keyword = keyword.upper()
    keyword_index = 0
    
    for char in ciphertext.upper():
        if char in string.ascii_uppercase:
            shift = ord(keyword[keyword_index % len(keyword)]) - ord('A')
            decrypted = (ord(char) - ord('A') - shift) % 26
            result.append(chr(decrypted + ord('A')))
            keyword_index += 1
        else:
            result.append(char)
    
    return ''.join(result)


def calculate_index_of_coincidence(text: str) -> float:
    """
    Calculate Index of Coincidence (IC) for text.
    
    IC measures how likely two random letters from the text are the same.
    - English text: IC ≈ 0.067
    - Random text: IC ≈ 0.038
    - Single Caesar shift: IC ≈ 0.067
    
    Args:
        text: Text to analyze (letters only)
        
    Returns:
        Index of Coincidence value
    """
    # Remove non-letters
    text = ''.join(c for c in text.upper() if c in string.ascii_uppercase)
    n = len(text)
    
    if n <= 1:
        return 0.0
    
    # Count letter frequencies
    freq = Counter(text)
    
    # Calculate IC: Σ(f_i * (f_i - 1)) / (n * (n - 1))
    numerator = sum(count * (count - 1) for count in freq.values())
    denominator = n * (n - 1)
    
    return numerator / denominator if denominator > 0 else 0.0


def find_repeated_sequences(ciphertext: str, sequence_length: int = 3) -> dict:
    """
    Find repeated sequences in ciphertext (Kasiski examination step 1).
    
    Args:
        ciphertext: Encrypted text
        sequence_length: Minimum length of sequences to find
        
    Returns:
        Dict mapping sequence to list of positions where it appears
    """
    # Remove non-letters
    text = ''.join(c for c in ciphertext.upper() if c in string.ascii_uppercase)
    
    sequences = {}
    
    # Find all sequences of given length
    for i in range(len(text) - sequence_length + 1):
        seq = text[i:i + sequence_length]
        
        if seq not in sequences:
            sequences[seq] = []
        sequences[seq].append(i)
    
    # Keep only sequences that appear more than once
    repeated = {seq: positions for seq, positions in sequences.items() 
                if len(positions) > 1}
    
    return repeated


def find_distances(positions: List[int]) -> List[int]:
    """
    Calculate distances between sequence occurrences.
    
    Args:
        positions: List of positions where sequence appears
        
    Returns:
        List of distances between consecutive occurrences
    """
    distances = []
    for i in range(len(positions) - 1):
        distances.append(positions[i + 1] - positions[i])
    return distances


def gcd(a: int, b: int) -> int:
    """Calculate Greatest Common Divisor."""
    while b:
        a, b = b, a % b
    return a


def find_gcd_of_list(numbers: List[int]) -> int:
    """Find GCD of a list of numbers."""
    if not numbers:
        return 0
    result = numbers[0]
    for num in numbers[1:]:
        result = gcd(result, num)
    return result


def kasiski_examination(ciphertext: str) -> List[int]:
    """
    Perform Kasiski examination to find likely keyword lengths.
    
    Process:
    1. Find repeated sequences in ciphertext
    2. Calculate distances between repetitions
    3. Find GCD of distances (likely keyword length or multiple)
    
    Args:
        ciphertext: Encrypted text
        
    Returns:
        List of likely keyword lengths (sorted by probability)
    """
    # Find repeated 3-letter sequences
    repeated = find_repeated_sequences(ciphertext, sequence_length=3)
    
    if not repeated:
        return []
    
    all_distances = []
    
    print("Repeated sequences found:")
    for seq, positions in sorted(repeated.items(), key=lambda x: len(x[1]), reverse=True)[:10]:
        distances = find_distances(positions)
        all_distances.extend(distances)
        print(f"  '{seq}' appears at positions {positions}, distances: {distances}")
    
    if not all_distances:
        return []
    
    # Find common factors of distances
    max_length = 20  # Check keyword lengths up to 20
    factor_counts = Counter()
    
    for distance in all_distances:
        for length in range(2, min(max_length + 1, distance + 1)):
            if distance % length == 0:
                factor_counts[length] += 1
    
    # Return most common factors as likely keyword lengths
    likely_lengths = [length for length, _ in factor_counts.most_common(5)]
    
    print(f"\nLikely keyword lengths: {likely_lengths}")
    return likely_lengths


def split_by_keyword_positions(ciphertext: str, keyword_length: int) -> List[str]:
    """
    Split ciphertext into groups based on keyword position.
    
    Each group contains letters encrypted with the same keyword letter.
    
    Args:
        ciphertext: Encrypted text
        keyword_length: Length of keyword
        
    Returns:
        List of strings, one for each keyword position
    """
    # Remove non-letters
    text = ''.join(c for c in ciphertext.upper() if c in string.ascii_uppercase)
    
    groups = ['' for _ in range(keyword_length)]
    
    for i, char in enumerate(text):
        groups[i % keyword_length] += char
    
    return groups


def find_caesar_shift_by_frequency(ciphertext: str) -> int:
    """
    Find most likely Caesar shift using frequency analysis.
    
    Assumes ciphertext is English encrypted with single Caesar shift.
    
    Args:
        ciphertext: Encrypted text
        
    Returns:
        Most likely shift value
    """
    text = ''.join(c for c in ciphertext.upper() if c in string.ascii_uppercase)
    
    if not text:
        return 0
    
    # Count letter frequencies
    freq = Counter(text)
    most_common_letter = freq.most_common(1)[0][0]
    
    # Assume most common letter is 'E'
    shift = (ord(most_common_letter) - ord('E')) % 26
    
    return shift


def break_vigenere_cipher(ciphertext: str) -> Tuple[str, str]:
    """
    Break Vigenère cipher using Kasiski examination and frequency analysis.
    
    Process:
    1. Find likely keyword length using Kasiski examination
    2. Split ciphertext by keyword position
    3. Perform frequency analysis on each group (treat as Caesar cipher)
    4. Reconstruct keyword and decrypt
    
    Args:
        ciphertext: Encrypted text to break
        
    Returns:
        Tuple of (keyword, decrypted_text)
    """
    print("=" * 70)
    print("BREAKING VIGENÈRE CIPHER")
    print("=" * 70)
    
    # Step 1: Find keyword length
    print("\nStep 1: Finding keyword length...")
    likely_lengths = kasiski_examination(ciphertext)
    
    if not likely_lengths:
        print("Could not determine keyword length")
        return "", ""
    
    best_keyword = ""
    best_plaintext = ""
    best_ic = 0
    
    # Try each likely length
    for keyword_length in likely_lengths[:3]:  # Try top 3 lengths
        print(f"\nStep 2: Trying keyword length {keyword_length}...")
        
        # Step 2: Split ciphertext by keyword position
        groups = split_by_keyword_positions(ciphertext, keyword_length)
        
        # Step 3: Find Caesar shift for each group
        keyword = ""
        for i, group in enumerate(groups):
            shift = find_caesar_shift_by_frequency(group)
            keyword_letter = chr(shift + ord('A'))
            keyword += keyword_letter
            print(f"  Position {i+1}: shift={shift}, keyword letter='{keyword_letter}'")
        
        # Step 4: Decrypt with found keyword
        plaintext = vigenere_decrypt(ciphertext, keyword)
        
        # Calculate IC to verify (should be close to English IC)
        ic = calculate_index_of_coincidence(plaintext)
        print(f"  Keyword: '{keyword}'")
        print(f"  Index of Coincidence: {ic:.4f} (English ≈ 0.067)")
        
        if ic > best_ic:
            best_ic = ic
            best_keyword = keyword
            best_plaintext = plaintext
    
    return best_keyword, best_plaintext


def demonstrate_vigenere_cipher():
    """Interactive demonstration of Vigenère cipher and attacks."""
    print("=" * 70)
    print("VIGENÈRE CIPHER DEMONSTRATION")
    print("=" * 70)
    
    # Example 1: Basic encryption/decryption
    print("\n[EXAMPLE 1] Basic Encryption/Decryption")
    print("-" * 70)
    plaintext = "HELLO WORLD FROM TRONDHEIM"
    keyword = "KEY"
    
    ciphertext = vigenere_encrypt(plaintext, keyword)
    decrypted = vigenere_decrypt(ciphertext, keyword)
    
    print(f"Plaintext:  {plaintext}")
    print(f"Keyword:    {keyword}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted:  {decrypted}")
    print(f"✓ Correct:  {plaintext == decrypted}")
    
    # Example 2: How keyword repeats
    print("\n[EXAMPLE 2] Keyword Repetition")
    print("-" * 70)
    plaintext = "ATTACK AT DAWN"
    keyword = "CIPHER"
    
    print(f"Plaintext: {plaintext}")
    print(f"Keyword:   {keyword * (len(plaintext) // len(keyword) + 1)[:len(plaintext)]}")
    
    ciphertext = vigenere_encrypt(plaintext, keyword)
    print(f"Ciphertext: {ciphertext}")
    
    # Example 3: Index of Coincidence
    print("\n[EXAMPLE 3] Index of Coincidence Analysis")
    print("-" * 70)
    
    english_text = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    random_text = "XQZPVJKLMNSDFGHJKWERTYUIOASDFGHJKLZXCVBN"
    caesar_encrypted = vigenere_encrypt(english_text, "E")  # Single shift
    vigenere_encrypted = vigenere_encrypt(english_text, "SECRET")
    
    print(f"English text IC:        {calculate_index_of_coincidence(english_text):.4f}")
    print(f"Random text IC:         {calculate_index_of_coincidence(random_text):.4f}")
    print(f"Caesar encrypted IC:    {calculate_index_of_coincidence(caesar_encrypted):.4f}")
    print(f"Vigenère encrypted IC:  {calculate_index_of_coincidence(vigenere_encrypted):.4f}")
    print("\nNote: Caesar maintains English IC, Vigenère reduces it")
    
    # Example 4: Breaking Vigenère cipher
    print("\n[EXAMPLE 4] Breaking Vigenère Cipher")
    print("-" * 70)
    
    # Create a longer text for better cryptanalysis
    long_plaintext = """
    THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG THE QUICK BROWN FOX
    JUMPS OVER THE LAZY DOG THE QUICK BROWN FOX JUMPS OVER THE LAZY
    DOG THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG
    """
    long_plaintext = ''.join(c for c in long_plaintext.upper() if c in string.ascii_uppercase)
    
    secret_keyword = "CRYPTO"
    encrypted = vigenere_encrypt(long_plaintext, secret_keyword)
    
    print(f"Original keyword: {secret_keyword}")
    print(f"Ciphertext length: {len(encrypted)} characters")
    print(f"Ciphertext (first 70 chars): {encrypted[:70]}...")
    
    # Attempt to break it
    found_keyword, decrypted = break_vigenere_cipher(encrypted)
    
    print(f"\n{'='*70}")
    print(f"RESULTS:")
    print(f"Found keyword: {found_keyword}")
    print(f"Correct keyword: {secret_keyword}")
    print(f"Match: {'✓ YES' if found_keyword == secret_keyword else '✗ NO (but close!)'}")
    
    if decrypted:
        print(f"\nDecrypted (first 70 chars): {decrypted[:70]}...")
        print(f"Original  (first 70 chars): {long_plaintext[:70]}...")
    
    # Example 5: Security lessons
    print("\n[EXAMPLE 5] Why Vigenère is Insecure")
    print("-" * 70)
    print("Reasons Vigenère cipher should NEVER be used for real security:")
    print("1. Kasiski examination reveals keyword length")
    print("2. Once length known, reduces to multiple Caesar ciphers")
    print("3. Frequency analysis breaks each Caesar component")
    print("4. Index of Coincidence test detects polyalphabetic encryption")
    print("\n✓ Use modern encryption (AES-256) instead!")


if __name__ == "__main__":
    # Run demonstration
    demonstrate_vigenere_cipher()
    
    # Interactive mode
    print("\n" + "=" * 70)
    print("INTERACTIVE MODE")
    print("=" * 70)
    
    while True:
        print("\nOptions:")
        print("1. Encrypt a message")
        print("2. Decrypt a message")
        print("3. Break Vigenère cipher (cryptanalysis)")
        print("4. Calculate Index of Coincidence")
        print("5. Exit")
        
        choice = input("\nChoose option (1-5): ").strip()
        
        if choice == '1':
            text = input("Enter plaintext: ").strip()
            keyword = input("Enter keyword: ").strip()
            result = vigenere_encrypt(text, keyword)
            print(f"Encrypted: {result}")
            
        elif choice == '2':
            text = input("Enter ciphertext: ").strip()
            keyword = input("Enter keyword: ").strip()
            result = vigenere_decrypt(text, keyword)
            print(f"Decrypted: {result}")
            
        elif choice == '3':
            text = input("Enter ciphertext to break (needs to be long, 200+ chars): ").strip()
            if len(text) < 100:
                print("Warning: Ciphertext may be too short for reliable cryptanalysis")
            keyword, plaintext = break_vigenere_cipher(text)
            if keyword:
                print(f"\nFound keyword: {keyword}")
                print(f"Decrypted text: {plaintext[:200]}...")
            
        elif choice == '4':
            text = input("Enter text to analyze: ").strip()
            ic = calculate_index_of_coincidence(text)
            print(f"Index of Coincidence: {ic:.4f}")
            print(f"English text: ≈0.067, Random: ≈0.038")
            
        elif choice == '5':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")
