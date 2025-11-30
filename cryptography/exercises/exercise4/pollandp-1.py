"""
Pollard's p-1 Attack Implementation

The attack works when one of the prime factors p of n = p*q
has the property that (p-1) is B-smooth, meaning all prime
factors of (p-1) are less than or equal to B.

Algorithm:
1. Choose a base a (typically 2)
2. Compute a^(B!) mod n by raising a to successive prime powers
3. Compute gcd(a^(B!) - 1, n)
4. If 1 < gcd < n, we've found a factor

Mathematical basis:
- If (p-1) is B-smooth, then (p-1) | B!
- By Fermat's Little Theorem: a^(p-1) ≡ 1 (mod p)
- Therefore: a^(B!) ≡ 1 (mod p)
- So: p | (a^(B!) - 1)
- Thus: gcd(a^(B!) - 1, n) = p
"""

import math


def gcd(a, b):
    """Compute greatest common divisor using Euclidean algorithm."""
    while b:
        a, b = b, a % b
    return a


def is_prime(n):
    """Check if n is prime."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(math.sqrt(n)) + 1, 2):
        if n % i == 0:
            return False
    return True


def get_primes_up_to(B):
    """Return list of all primes up to B."""
    primes = []
    for i in range(2, B + 1):
        if is_prime(i):
            primes.append(i)
    return primes


def pollard_p_minus_1(n, B, a=2, verbose=True):
    """
    Pollard's p-1 factorization method.
    
    Args:
        n: Number to factor (should be composite, n = p*q)
        B: Smoothness bound
        a: Base (default 2)
        verbose: Print detailed steps
        
    Returns:
        A factor of n if found, otherwise None
    """
    if verbose:
        print(f"{'='*70}")
        print(f"POLLARD'S P-1 ATTACK")
        print(f"{'='*70}")
        print(f"n = {n}")
        print(f"B = {B} (smoothness bound)")
        print(f"a = {a} (base)")
        print()
    
    # Get all primes up to B
    primes = get_primes_up_to(B)
    if verbose:
        print(f"Primes ≤ {B}: {primes}")
        print()
    
    # Compute a^(B!) mod n incrementally
    # Instead of computing B! directly (which is huge), we raise a
    # to each prime power that divides B!
    result = a
    
    if verbose:
        print("Computing a^(B!) mod n incrementally:")
        print(f"Starting with a^1 = {result}")
        print()
    
    for prime in primes:
        # Find the highest power of prime that is ≤ B
        # This is floor(log_prime(B))
        power = int(math.log(B) / math.log(prime))
        exponent = prime ** power
        
        if verbose:
            print(f"Prime {prime}: highest power ≤ {B} is {prime}^{power} = {exponent}")
        
        # Raise result to this prime power
        result = pow(result, exponent, n)
        
        if verbose:
            print(f"  a^(...*{exponent}) mod {n} = {result}")
            print()
    
    if verbose:
        print(f"Final: a^(B!) mod n = {result}")
        print()
    
    # Compute gcd(a^(B!) - 1, n)
    d = gcd(result - 1, n)
    
    if verbose:
        print(f"Computing gcd(a^(B!) - 1, n):")
        print(f"  gcd({result} - 1, {n}) = gcd({result - 1}, {n}) = {d}")
        print()
    
    if d > 1 and d < n:
        if verbose:
            print(f"{'='*70}")
            print(f"✓ SUCCESS! Found factor: {d}")
            print(f"{'='*70}")
            print(f"  n = {n}")
            print(f"  p = {d}")
            print(f"  q = {n // d}")
            print(f"  Verification: {d} × {n // d} = {d * (n // d)}")
            
            # Check smoothness
            p_minus_1 = d - 1
            print()
            print(f"Factorization of (p-1) = {p_minus_1}:")
            factors = factorize(p_minus_1)
            print(f"  {p_minus_1} = {' × '.join(map(str, factors))}")
            max_factor = max(factors)
            print(f"  Largest prime factor: {max_factor}")
            print(f"  Is {d-1}-smooth with B={B}? {max_factor <= B}")
            print(f"{'='*70}")
        return d
    elif d == n:
        if verbose:
            print(f"✗ FAILURE: gcd = n (try larger B or different a)")
        return None
    else:
        if verbose:
            print(f"✗ FAILURE: gcd = 1 (p-1 is not {B}-smooth, try larger B)")
        return None


def factorize(n):
    """Return list of prime factors of n."""
    factors = []
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.append(d)
            n //= d
        d += 1
    if n > 1:
        factors.append(n)
    return factors


def main():
    """Main function to demonstrate Pollard's p-1 attack."""
    
    # Example from your code
    n = 1829
    B = 5
    
    print("\n" + "="*70)
    print("EXAMPLE 1: n = 1829, B = 5")
    print("="*70 + "\n")
    
    factor = pollard_p_minus_1(n, B, a=2, verbose=True)
    
    # Try with larger B if it failed
    if factor is None:
        print("\n" + "="*70)
        print("Let's try with a larger smoothness bound B = 20")
        print("="*70 + "\n")
        factor = pollard_p_minus_1(n, B=20, a=2, verbose=True)
    
    # Another example
    print("\n" + "="*70)
    print("EXAMPLE 2: n = 299, B = 5")
    print("="*70 + "\n")
    print("This is a classic example where p-1 = 12 = 2² × 3")
    print("Since max prime factor of (p-1) is 3 ≤ 5, attack should work!")
    print()
    
    n2 = 299  # 13 × 23, where 13-1 = 12 = 2² × 3
    factor2 = pollard_p_minus_1(n2, B=5, a=2, verbose=True)
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print("\nPollard's p-1 works when (p-1) has only small prime factors.")
    print("The attack computes a^(B!) mod n efficiently by raising to")
    print("each prime power ≤ B, then checks gcd(a^(B!) - 1, n).")
    print("\nKey insight: If all prime factors of (p-1) are ≤ B, then")
    print("(p-1) divides B!, so a^(B!) ≡ 1 (mod p) by Fermat's theorem.")
    print("="*70)


if __name__ == "__main__":
    main()

