#Polland p-1 Attack Implementation
import math

#let  n = p * q
#We will try to find p

n = 1829
B = 5


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def mod_exp(a, B, n):
    b = a**(math.factorial(B)) % n
    return b

for a in range(2, n):
    a_b = mod_exp(a, B, n)
    d = gcd(a_b - 1, n)
    if d > 1 and d < n:
        q = n // d
        print(f"Found factor: {d}")
        print(f"Corresponding cofactor: {q}")
        break
    

