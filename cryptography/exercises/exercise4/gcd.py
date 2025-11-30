#gcd calculation

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

a1 = 1674292
a2 = 2407596
a3 = 2566564
a4 = 2597332

d = 3
print(f"gcd({d}, {a1}) = {gcd(d, a1)}")
print(f"gcd({d}, {a2}) = {gcd(d, a2)}")
print(f"gcd({d}, {a3}) = {gcd(d, a3)}")
print(f"gcd({d}, {a4}) = {gcd(d, a4)}")