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


p = 1283
q = 2027
d = 3
n = p * q
phi = (p - 1) * (q - 1)
e = mod_inverse(d, phi)

print(f"Public exponent e: {e}")