#diffie hellman key exchange implementation

prime = 101
base = 3
a = 33
b = 65

def power_mod(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if (exp % 2) == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

A = power_mod(base, a, prime)
B = power_mod(base, b, prime)
shared_key_a = power_mod(B, a, prime)
shared_key_b = power_mod(A, b, prime)
print(f"Shared key computed by A: {shared_key_a}")
print(f"Shared key computed by B: {shared_key_b}")


for i in range(1, 100):
    print(f"5^{i} mod 101 = {power_mod(5, i, 101)}")
