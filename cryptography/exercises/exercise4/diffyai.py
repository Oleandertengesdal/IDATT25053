
"""
Diffie-Hellman Key Exchange - Problem 5

Alice and Bob want to have a common key using Diffie-Hellman.
- Prime p = 101
- Base n = 3
- Alice's secret: a = 33
- Bob's secret: b = 65

Part a) Compare sequences 3^i and 5^i for i = 1,...,100 (mod 101)
Part b) Find their common key
"""


def power_mod(base, exp, mod):
    """
    Efficient modular exponentiation using binary method.
    Computes (base^exp) mod mod
    """
    result = 1
    base = base % mod
    while exp > 0:
        if (exp % 2) == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result


def analyze_powers(base, prime, max_exp=100):
    """
    Analyze the sequence of powers base^i mod prime for i = 1 to max_exp.
    
    Returns:
        - List of all powers
        - Set of unique values
        - Period (if sequence repeats)
    """
    powers = []
    seen = {}
    
    for i in range(1, max_exp + 1):
        power = power_mod(base, i, prime)
        powers.append(power)
        
        # Check for period (when does it repeat to the first value?)
        if power == powers[0] and i > 1 and i not in seen:
            period = i
            break
    else:
        # No period found within max_exp
        period = None
    
    unique_values = set(powers)
    
    return powers, unique_values, period


def is_primitive_root(base, prime):
    """
    Check if base is a primitive root modulo prime.
    A primitive root generates all non-zero elements mod p.
    """
    # For a prime p, a primitive root generates p-1 distinct values
    powers, unique_values, period = analyze_powers(base, prime, prime - 1)
    return len(unique_values) == (prime - 1)


def main():
    """Main function to solve both parts of the problem."""
    
    # Given parameters
    prime = 101
    base = 3
    alice_secret = 33
    bob_secret = 65
    
    print("="*70)
    print("DIFFIE-HELLMAN KEY EXCHANGE")
    print("="*70)
    print(f"\nParameters:")
    print(f"  Prime p: {prime}")
    print(f"  Base n: {base}")
    print(f"  Alice's secret a: {alice_secret}")
    print(f"  Bob's secret b: {bob_secret}")
    
    # ====================================================================
    # PART A: Compare 3^i and 5^i sequences
    # ====================================================================
    print("\n" + "="*70)
    print("PART A: ANALYZING POWER SEQUENCES")
    print("="*70)
    
    # Analyze base = 3
    print(f"\n--- Analyzing 3^i mod {prime} for i = 1,...,100 ---")
    powers_3, unique_3, period_3 = analyze_powers(3, prime, 100)
    
    print(f"\nFirst 20 values of 3^i mod {prime}:")
    for i in range(20):
        print(f"  3^{i+1} mod {prime} = {powers_3[i]}")
    
    print(f"\nStatistics for 3^i mod {prime}:")
    print(f"  Number of unique values: {len(unique_3)} out of {prime-1} possible")
    print(f"  Period: {period_3 if period_3 else 'Not found within 100 iterations'}")
    print(f"  Is primitive root? {is_primitive_root(3, prime)}")
    
    if is_primitive_root(3, prime):
        print(f"  ✓ Base 3 is a PRIMITIVE ROOT mod {prime}")
        print(f"    It generates all {prime-1} non-zero elements mod {prime}")
    
    # Analyze base = 5
    print(f"\n--- Analyzing 5^i mod {prime} for i = 1,...,100 ---")
    powers_5, unique_5, period_5 = analyze_powers(5, prime, 100)
    
    print(f"\nFirst 20 values of 5^i mod {prime}:")
    for i in range(20):
        print(f"  5^{i+1} mod {prime} = {powers_5[i]}")
    
    print(f"\nStatistics for 5^i mod {prime}:")
    print(f"  Number of unique values: {len(unique_5)} out of {prime-1} possible")
    print(f"  Period: {period_5 if period_5 else 'Not found within 100 iterations'}")
    print(f"  Is primitive root? {is_primitive_root(5, prime)}")
    
    if not is_primitive_root(5, prime):
        print(f"  ✗ Base 5 is NOT a primitive root mod {prime}")
        print(f"    It only generates {len(unique_5)} distinct values, not all {prime-1}")
    
    # Major difference
    print("\n" + "="*70)
    print("MAJOR DIFFERENCE:")
    print("="*70)
    print(f"\n3^i mod {prime}:")
    print(f"  - Generates {len(unique_3)} unique values")
    print(f"  - {'IS' if is_primitive_root(3, prime) else 'is NOT'} a primitive root")
    
    print(f"\n5^i mod {prime}:")
    print(f"  - Generates {len(unique_5)} unique values")
    print(f"  - {'IS' if is_primitive_root(5, prime) else 'is NOT'} a primitive root")
    
    print(f"\nConclusion:")
    if is_primitive_root(3, prime) and not is_primitive_root(5, prime):
        print(f"  Base 3 generates ALL non-zero elements mod {prime} (primitive root)")
        print(f"  Base 5 only generates a SUBSET of elements (not a primitive root)")
        print(f"  This makes base 3 SUITABLE for Diffie-Hellman (provides more security)")
        print(f"  Base 5 is UNSUITABLE as it doesn't generate the full group")
    
    # ====================================================================
    # PART B: Find common key
    # ====================================================================
    print("\n" + "="*70)
    print("PART B: DIFFIE-HELLMAN KEY EXCHANGE")
    print("="*70)
    
    print(f"\nStep 1: Alice computes A = {base}^{alice_secret} mod {prime}")
    A = power_mod(base, alice_secret, prime)
    print(f"  A = {A}")
    print(f"  Alice sends A = {A} to Bob (publicly)")
    
    print(f"\nStep 2: Bob computes B = {base}^{bob_secret} mod {prime}")
    B = power_mod(base, bob_secret, prime)
    print(f"  B = {B}")
    print(f"  Bob sends B = {B} to Alice (publicly)")
    
    print(f"\nStep 3: Alice computes shared key = B^a mod {prime}")
    shared_key_alice = power_mod(B, alice_secret, prime)
    print(f"  K_Alice = {B}^{alice_secret} mod {prime} = {shared_key_alice}")
    
    print(f"\nStep 4: Bob computes shared key = A^b mod {prime}")
    shared_key_bob = power_mod(A, bob_secret, prime)
    print(f"  K_Bob = {A}^{bob_secret} mod {prime} = {shared_key_bob}")
    
    print(f"\nVerification:")
    print(f"  K_Alice = {shared_key_alice}")
    print(f"  K_Bob = {shared_key_bob}")
    print(f"  Match: {shared_key_alice == shared_key_bob} {'✓' if shared_key_alice == shared_key_bob else '✗'}")
    
    print(f"\n{'='*70}")
    print(f"✓ COMMON KEY: {shared_key_alice}")
    print(f"{'='*70}")
    
    # Mathematical verification
    print(f"\nMathematical verification:")
    print(f"  Alice: K = B^a = ({base}^b)^a = {base}^(b×a) = {base}^({bob_secret}×{alice_secret}) mod {prime}")
    print(f"  Bob:   K = A^b = ({base}^a)^b = {base}^(a×b) = {base}^({alice_secret}×{bob_secret}) mod {prime}")
    print(f"  Both compute: {base}^{alice_secret * bob_secret} mod {prime}")
    
    verification = power_mod(base, alice_secret * bob_secret, prime)
    print(f"  Direct calculation: {base}^{alice_secret * bob_secret} mod {prime} = {verification}")
    print(f"  Matches common key: {verification == shared_key_alice} ✓")
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"\nPart a) Major difference between 3^i and 5^i mod {prime}:")
    print(f"  - 3 is a primitive root (generates all {len(unique_3)} non-zero elements)")
    print(f"  - 5 is NOT a primitive root (generates only {len(unique_5)} elements)")
    print(f"  - Primitive roots are essential for secure Diffie-Hellman!")
    print(f"\nPart b) Common key: {shared_key_alice}")
    print(f"\nPublic information (known to eavesdropper):")
    print(f"  p = {prime}, n = {base}, A = {A}, B = {B}")
    print(f"Private information (secrets):")
    print(f"  Alice knows: a = {alice_secret}")
    print(f"  Bob knows: b = {bob_secret}")
    print(f"Shared secret (secure):")
    print(f"  Common key K = {shared_key_alice}")
    print("="*70)


if __name__ == "__main__":
    main()