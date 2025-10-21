alphabet = "abcdefghijklmnopqrstuvwxyz"

def f(x):
    return (3*x + 11) % len(alphabet)

def f_inverse(y):
    return (9 * y - 21) % len(alphabet)

def encrypt(message):
    """Encrypt a message using the affine cipher"""
    result = ""
    for char in message.lower():
        if char in alphabet:
            idx = alphabet.index(char)
            cipher_idx = f(idx)
            result += alphabet[cipher_idx].upper()  # Cipher text in uppercase
        else:
            result += char  # Leave spaces/punctuation as-is
    return result

def decrypt(ciphertext):
    """Decrypt a message using the affine cipher"""
    result = ""
    for char in ciphertext.lower():
        if char in alphabet:
            idx = alphabet.index(char)
            plain_idx = f_inverse(idx)
            result += alphabet[plain_idx]
        else:
            result += char
    return result

if __name__ == '__main__':
    # Task a: show the permutation
    print("Task a: Encryption permutation")
    for i in range(len(alphabet)):
        res = f(i)
        print(f"{alphabet[i]} -> {alphabet[res].upper()}")

    print("\nTask c: Decryption permutation")
    for i in range(len(alphabet)):
        res = f_inverse(i)
        print(f"{alphabet[i].upper()} -> {alphabet[res]}")

    # Example encryption
    plaintext = "alice"
    ciphertext = encrypt(plaintext)
    print(f"\nEncrypt '{plaintext}': {ciphertext}")

    # Example decryption
    decrypted = decrypt(ciphertext)
    print(f"Decrypt '{ciphertext}': {decrypted}")
