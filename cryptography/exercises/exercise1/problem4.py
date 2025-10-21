"""RGMRQ ERQMZ MZXMD ENNZU QFD"""


#Affine cipher brute force

alphabet = "abcdefghijklmnopqrstuvwxyz"

# key = (a, b)

#function affine: f(x) = (a*x + b) mod m
def f(a, b, x):
    return (a*x + b) % len(alphabet), a, b

def f_inverse(a, b, y):
    a_inv = pow(a, -1, len(alphabet))
    return (a_inv * (y - b)) % len(alphabet)


def encrypt(a, b, message):
    """Encrypt a message using the affine cipher"""
    result = ""
    for char in message.lower():
        if char in alphabet:
            idx = alphabet.index(char)
            cipher_idx, _, _ = f(a, b, idx)
            result += alphabet[cipher_idx].upper()  # Cipher text in uppercase
        else:
            result += char  # Leave spaces/punctuation as-is
    return result

def decrypt(a, b, ciphertext):
    """Decrypt a message using the affine cipher"""
    result = ""
    for char in ciphertext.lower():
        if char in alphabet:
            idx = alphabet.index(char)
            plain_idx = f_inverse(a, b, idx)
            result += alphabet[plain_idx]
        else:
            result += char
    return result
def brute_force_affine(ciphertext):
    """Try all possible affine cipher keys"""
    results = []
    for a in range(1, len(alphabet)):
        if gcd(a, len(alphabet)) != 1:
            continue  # Skip if 'a' is not coprime with alphabet length
        for b in range(len(alphabet)):
            decrypted_text = decrypt(a, b, ciphertext)
            results.append((a, b, decrypted_text))
    return results

def gcd(x, y):
    while y:
        x, y = y, x % y
    return x
if __name__ == '__main__':

    brutforcetext = "RGMRQERQMZMZXMDENNZUQFD"
    brutforceresults = brute_force_affine(brutforcetext)
    for a, b, decrypted in brutforceresults:
        print(f"a={a}, b={b} -> {decrypted}")
    print("\n")
