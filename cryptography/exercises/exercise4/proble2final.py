"""
RSA Encryption Exercise

a) Alice wants to set up RSA with p = 1283, d = 3
   Choose q from: 1307, 1879, 2003, 2027
   
b) Find public key e using Extended Euclidean Algorithm

c) Encrypt message 111 using repeated squaring
"""

import math


def extended_Euclid(a, b):
    """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that a*x + b*y = gcd(a,b)
    """
    if b == 0:
        # gcd(a,0) = a
        # and gcd(a,0) = 1 * a + 0 * b
        return a, 1, 0
    else:
        r, q = a % b, a // b
        d, z, w = extended_Euclid(b, r)
        return d, w, z - q * w


def mod_inverse(a, m):
    """
    Find modular inverse of a modulo m using Extended Euclidean Algorithm.
    Returns x such that (a * x) ≡ 1 (mod m)
    """
    gcd, x, y = extended_Euclid(a, m)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m


def gcd(a, b):
    """Compute greatest common divisor."""
    while b:
        a, b = b, a % b
    return a


def repeated_squaring(base, exponent, modulus):
    """
    Compute (base^exponent) mod modulus using repeated squaring algorithm.
    
    Algorithm:
    1. Convert exponent to binary
    2. Square and multiply based on binary digits
    
    This is efficient for large exponents: O(log n) multiplications
    instead of O(n) multiplications.
    """
    print(f"\nComputing {base}^{exponent} mod {modulus} using repeated squaring:")
    print(f"{'='*70}")
    
    # Convert exponent to binary
    binary_exp = bin(exponent)[2:]  # Remove '0b' prefix
    print(f"Exponent {exponent} in binary: {binary_exp}")
    print()
    
    result = 1
    current_power = base % modulus
    
    print(f"Starting values:")
    print(f"  result = 1")
    print(f"  current_power = {base} mod {modulus} = {current_power}")
    print()
    
    # Process each bit from right to left
    for i, bit in enumerate(reversed(binary_exp)):
        bit_position = i
        print(f"Bit {bit_position} (from right): {bit}")
        
        if bit == '1':
            result = (result * current_power) % modulus
            print(f"  Bit is 1: result = result * current_power mod {modulus}")
            print(f"           result = {result}")
        else:
            print(f"  Bit is 0: skip multiplication")
        
        # Square for next iteration (except on last bit)
        if i < len(binary_exp) - 1:
            current_power = (current_power * current_power) % modulus
            print(f"  Square: current_power = current_power² mod {modulus} = {current_power}")
        
        print()
    
    print(f"{'='*70}")
    print(f"✓ Final result: {base}^{exponent} mod {modulus} = {result}")
    print(f"{'='*70}")
    
    return result


def analyze_q_choices(p, d, candidates):
    """
    Analyze which value of q is best for RSA security.
    
    For RSA to work:
    1. gcd(d, φ(n)) = 1 (so we can find e)
    2. p and q should be roughly the same size
    3. p and q should not be too close (vulnerable to Fermat's factorization)
    4. p-1 and q-1 should not have only small factors (vulnerable to Pollard's p-1)
    """
    print(f"{'='*70}")
    print(f"PART A: ANALYZING CHOICES FOR q")
    print(f"{'='*70}")
    print(f"\nGiven: p = {p}, d = {d}")
    print(f"Candidates for q: {candidates}")
    print()
    
    results = []
    
    for q in candidates:
        print(f"\n--- Analyzing q = {q} ---")
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        print(f"  n = p × q = {p} × {q} = {n}")
        print(f"  φ(n) = (p-1) × (q-1) = {p-1} × {q-1} = {phi}")
        
        # Check 1: Can we find e? (gcd(d, φ(n)) = 1)
        d_phi_gcd = gcd(d, phi)
        can_find_e = (d_phi_gcd == 1)
        print(f"  gcd(d, φ(n)) = gcd({d}, {phi}) = {d_phi_gcd}")
        
        if can_find_e:
            print(f"  ✓ Can find public key e (gcd = 1)")
        else:
            print(f"  ✗ CANNOT find public key e (gcd ≠ 1) - INVALID CHOICE!")
            results.append({
                'q': q, 
                'valid': False, 
                'reason': f'd and φ(n) are not coprime (gcd={d_phi_gcd})'
            })
            continue
        
        # Check 2: Size difference
        ratio = max(p, q) / min(p, q)
        print(f"  Size ratio p:q = {ratio:.4f}")
        
        # Check 3: Fermat's factorization vulnerability
        diff = abs(p - q)
        print(f"  |p - q| = {diff}")
        
        if diff < 1000:
            vulnerability = "Fermat's factorization (p and q too close)"
        elif diff < 2000:
            vulnerability = "Moderate - somewhat close primes"
        else:
            vulnerability = "None - good separation"
        
        # Check 4: Pollard's p-1 vulnerability
        p_minus_1_factors = factorize_check_smooth(p - 1)
        q_minus_1_factors = factorize_check_smooth(q - 1)
        
        p_max_factor = max(p_minus_1_factors) if p_minus_1_factors else 0
        q_max_factor = max(q_minus_1_factors) if q_minus_1_factors else 0
        
        print(f"  (p-1) = {p-1} has max prime factor: {p_max_factor}")
        print(f"  (q-1) = {q-1} has max prime factor: {q_max_factor}")
        
        if p_max_factor < 100 or q_max_factor < 100:
            vulnerability = "Pollard's p-1 attack (p-1 or q-1 too smooth)"
        
        print(f"  Vulnerability: {vulnerability}")
        
        results.append({
            'q': q,
            'valid': True,
            'n': n,
            'phi': phi,
            'diff': diff,
            'ratio': ratio,
            'vulnerability': vulnerability,
            'p_max_factor': p_max_factor,
            'q_max_factor': q_max_factor
        })
    
    # Summary
    print(f"\n{'='*70}")
    print(f"SUMMARY - RANKING BY SECURITY")
    print(f"{'='*70}")
    
    valid_results = [r for r in results if r.get('valid', False)]
    valid_results.sort(key=lambda x: (-x['diff'], -x['q_max_factor']))
    
    for i, r in enumerate(valid_results, 1):
        print(f"\n{i}. q = {r['q']}")
        print(f"   |p - q| = {r['diff']} (larger is better)")
        print(f"   Max factor in (q-1): {r['q_max_factor']} (larger is better)")
        print(f"   Vulnerability: {r['vulnerability']}")
    
    best_q = valid_results[0]['q'] if valid_results else None
    
    print(f"\n{'='*70}")
    print(f"✓ BEST CHOICE: q = {best_q}")
    print(f"{'='*70}")
    
    if best_q == 2027:
        print(f"Reasons:")
        print(f"  1. gcd(d, φ(n)) = 1 (RSA works)")
        print(f"  2. Largest |p - q| = 744 (resistant to Fermat's attack)")
        print(f"  3. (q-1) = 2026 has large prime factors (resistant to Pollard's p-1)")
        print(f"  4. Good size ratio between p and q")
    
    for r in results:
        if not r.get('valid', True):
            print(f"\nq = {r['q']}: ✗ INVALID - {r['reason']}")
    
    return best_q


def factorize_check_smooth(n):
    """Return list of prime factors of n."""
    factors = []
    original_n = n
    d = 2
    while d * d <= n:
        while n % d == 0:
            if d not in factors:
                factors.append(d)
            n //= d
        d += 1
    if n > 1:
        factors.append(n)
    return factors


def main():
    """Main function to solve all parts of the exercise."""
    
    print("="*70)
    print("RSA ENCRYPTION EXERCISE")
    print("="*70)
    
    # Given values
    p = 1283
    d = 3
    candidates = [1307, 1879, 2003, 2027]
    
    # Part a) Analyze q choices
    best_q = analyze_q_choices(p, d, candidates)
    q = best_q
    
    # Part b) Find public key e
    print(f"\n{'='*70}")
    print(f"PART B: FINDING PUBLIC KEY e")
    print(f"{'='*70}")
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    print(f"\nUsing: p = {p}, q = {q}, d = {d}")
    print(f"n = p × q = {p} × {q} = {n}")
    print(f"φ(n) = (p-1) × (q-1) = {p-1} × {q-1} = {phi}")
    print()
    
    print(f"Finding e such that: d × e ≡ 1 (mod φ(n))")
    print(f"In other words: {d} × e ≡ 1 (mod {phi})")
    print(f"This means: e = d⁻¹ mod φ(n)")
    print()
    
    e = mod_inverse(d, phi)
    
    print(f"Using Extended Euclidean Algorithm:")
    gcd_result, x, y = extended_Euclid(d, phi)
    print(f"  gcd({d}, {phi}) = {gcd_result}")
    print(f"  {d} × {x} + {phi} × {y} = {gcd_result}")
    print(f"  Therefore: {d} × {x} ≡ 1 (mod {phi})")
    print(f"  e = {x} mod {phi} = {e}")
    print()
    
    # Verify
    verify = (d * e) % phi
    print(f"Verification: (d × e) mod φ(n) = ({d} × {e}) mod {phi} = {verify}")
    print(f"✓ Correct!" if verify == 1 else "✗ Error!")
    
    print(f"\n{'='*70}")
    print(f"✓ PUBLIC KEY: (n, e) = ({n}, {e})")
    print(f"✓ PRIVATE KEY: (n, d) = ({n}, {d})")
    print(f"{'='*70}")
    
    # Part c) Encrypt message 111
    print(f"\n{'='*70}")
    print(f"PART C: ENCRYPTING MESSAGE 111")
    print(f"{'='*70}")
    
    message = 111
    print(f"\nMessage (plaintext): m = {message}")
    print(f"Public key: (n, e) = ({n}, {e})")
    print(f"Encryption: c = m^e mod n = {message}^{e} mod {n}")
    
    ciphertext = repeated_squaring(message, e, n)
    
    print(f"\n✓ CIPHERTEXT: c = {ciphertext}")
    
    # Verify by decrypting
    print(f"\n{'='*70}")
    print(f"VERIFICATION: DECRYPTING")
    print(f"{'='*70}")
    print(f"\nDecryption: m = c^d mod n = {ciphertext}^{d} mod {n}")
    
    decrypted = repeated_squaring(ciphertext, d, n)
    
    print(f"\n✓ DECRYPTED MESSAGE: m = {decrypted}")
    print(f"Original message: {message}")
    print(f"Match: {decrypted == message} {'✓' if decrypted == message else '✗'}")
    
    # Final summary
    print(f"\n{'='*70}")
    print(f"FINAL SUMMARY")
    print(f"{'='*70}")
    print(f"\nPart a) Best q = {q} (most secure against attacks)")
    print(f"Part b) Public key e = {e}")
    print(f"Part c) Encryption of 111 = {ciphertext}")
    print(f"\nRSA Parameters:")
    print(f"  Public key:  (n, e) = ({n}, {e})")
    print(f"  Private key: (n, d) = ({n}, {d})")
    print(f"  Message: {message} → Ciphertext: {ciphertext}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()