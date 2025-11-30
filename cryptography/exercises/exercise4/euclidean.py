#Extended Euclidean Algorithm to find modular inverse

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def extended_Euclid(a, b):
    if b == 0:
        # gcd(a,0) = a
        # and gcd(a,0) = 1 * a + 0 * b
        return a, 1, 0
    else:
        r, q = a % b, a // b
        d, z, w = extended_Euclid(b, r)
        return d, w, z - q * w

def mod_inverse(a, m):
    gcd, x, y = extended_Euclid(a, m)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m
    
def euclid(a, b):
    if b == 0:
        return a
    else:
        return euclid(b, a % b)

def mult_inverse(a, m):
    """Calculate modular multiplicative inverse of a under modulo m."""
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1


p = 1283
q = 2027
d = 3
n = p * q
phi = (p - 1) * (q - 1)
e = mod_inverse(d, phi)

check = euclid(e, phi)

print(f"Public exponent e: {e}")
print(f"gcd(e, phi): {check}")