# Function to count how many bits differ between two hex strings
def bit_difference(hex1, hex2):
    # Convert hex to integers
    n1 = int(hex1.replace(" ", ""), 16)
    n2 = int(hex2.replace(" ", ""), 16)

    # XOR to find differing bits, then count 1s
    xor_result = n1 ^ n2
    return bin(xor_result).count("1")

# === Input your ciphertexts here ===
ciphers = {
    "A": ("0023456789ABCDEF0123456789ABCDEF", "1023456789ABCDEF0123456789ABCDEF"),
    "B": ("F023456789ABCDEF0123456789ABCDEF", "0023456789ABCDEF0123456789ABCDEF"),
    "C": ("01fcf41f4c13eaaa96747c97c49b6222", "b8fcf41f5c13eaaa86747c97d49b6222"),
    "D": ("0694267ba398480c6b2b9f649be476cb", "7af49a8defad94fa27cb03ac9f1c149a")
}

# === Calculate and print results ===
for label, (k1, k2) in ciphers.items():
    diff = bit_difference(k1, k2)
    print(f"Cipher {label}: {diff} bits differ between K1 and K2")
