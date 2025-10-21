

K1 = "0123456789ABCDEF0123456789ABCDEF"
K2 = "1123456789ABCDEF0123456789ABCDEF"

X1 = "01000000000000000000000000000000"
X2 = "02000000000000000000000000000000"

k1 = bytes.fromhex(K1)
k2 = bytes.fromhex(K2)

x1 = bytes.fromhex(X1)
x2 = bytes.fromhex(X2)


# XOR one time

def otp_encrypt(key, plaintext):
    return bytes(a ^ b for a,b in zip(key, plaintext))

def otp_decrypt(key, ciphertext):
    return bytes(a ^ b for a,b in zip(key, ciphertext))

def affine_encrypt(key, plaintext):
    key_int = int.from_bytes(key, byteorder='big')
    p_int = int.from_bytes(plaintext, byteorder='big')
    m = 1 << 128
    a = key_int
    b = key_int
    c_int = (a * p_int + b) % m
    return c_int.to_bytes(16, byteorder='big')

def affine_decrypt(key, ciphertext):
    key_int = int.from_bytes(key, byteorder='big')
    c_int = int.from_bytes(ciphertext, byteorder='big')
    m = 1 << 128
    a = key_int
    b = key_int
    p_int = (pow(a, -1, m) * (c_int - b)) % m
    return p_int.to_bytes(16, byteorder='big')

def changed_bits(b1, b2):
    return sum(bin(b1_byte ^ b2_byte).count('1') for b1_byte, b2_byte in zip(b1, b2))


if __name__ == '__main__':
    print("=" * 80)
    print("ANALYZING KEY SENSITIVITY: How many bits change in ciphertext when key changes?")
    print("=" * 80)
    print()
    
    # Show the key difference
    print("Key Comparison:")
    print(f"K1: {k1.hex().upper()}")
    print(f"K2: {k2.hex().upper()}")
    print(f"Bits changed in key: {changed_bits(k1, k2)}")
    print()
    
    # Show the plaintext difference
    print("Plaintext Comparison:")
    print(f"X1: {x1.hex().upper()}")
    print(f"X2: {x2.hex().upper()}")
    print(f"Bits changed in plaintext: {changed_bits(x1, x2)}")
    print()
    print("=" * 80)
    
    # OTP with same plaintext, different keys
    print("\n[OTP] Same plaintext X1, different keys (K1 vs K2):")
    print("-" * 80)
    c1_otp = otp_encrypt(k1, x1)
    c2_otp = otp_encrypt(k2, x1)
    print(f"Plaintext:       {x1.hex().upper()}")
    print(f"Key K1:          {k1.hex().upper()}")
    print(f"Ciphertext C1:   {c1_otp.hex().upper()}")
    print()
    print(f"Key K2:          {k2.hex().upper()}")
    print(f"Ciphertext C2:   {c2_otp.hex().upper()}")
    print()
    print(f"→ Bits changed in CIPHERTEXT when key changed by 4 bits: {changed_bits(c1_otp, c2_otp)}")
    print()

    # OTP with different plaintext, same key
    print("[OTP] Same key K1, different plaintexts (X1 vs X2):")
    print("-" * 80)
    c1_otp_x1 = otp_encrypt(k1, x1)
    c1_otp_x2 = otp_encrypt(k1, x2)
    print(f"Key K1:          {k1.hex().upper()}")
    print(f"Plaintext X1:    {x1.hex().upper()}")
    print(f"Ciphertext C1:   {c1_otp_x1.hex().upper()}")
    print()
    print(f"Plaintext X2:    {x2.hex().upper()}")
    print(f"Ciphertext C2:   {c1_otp_x2.hex().upper()}")
    print()
    print(f"→ Bits changed in CIPHERTEXT when plaintext changed by 1 bit: {changed_bits(c1_otp_x1, c1_otp_x2)}")
    print()
    print("=" * 80)

    # Affine with same plaintext, different keys
    print("\n[AFFINE] Same plaintext X1, different keys (K1 vs K2):")
    print("-" * 80)
    c1_affine = affine_encrypt(k1, x1)
    c2_affine = affine_encrypt(k2, x1)
    print(f"Plaintext:       {x1.hex().upper()}")
    print(f"Key K1:          {k1.hex().upper()}")
    print(f"Ciphertext C1:   {c1_affine.hex().upper()}")
    print()
    print(f"Key K2:          {k2.hex().upper()}")
    print(f"Ciphertext C2:   {c2_affine.hex().upper()}")
    print()
    print(f"→ Bits changed in CIPHERTEXT when key changed by 4 bits: {changed_bits(c1_affine, c2_affine)}")
    print()

    # Affine with different plaintext, same key
    print("[AFFINE] Same key K1, different plaintexts (X1 vs X2):")
    print("-" * 80)
    c1_affine_x1 = affine_encrypt(k1, x1)
    c1_affine_x2 = affine_encrypt(k1, x2)
    print(f"Key K1:          {k1.hex().upper()}")
    print(f"Plaintext X1:    {x1.hex().upper()}")
    print(f"Ciphertext C1:   {c1_affine_x1.hex().upper()}")
    print()
    print(f"Plaintext X2:    {x2.hex().upper()}")
    print(f"Ciphertext C2:   {c1_affine_x2.hex().upper()}")
    print()
    print(f"→ Bits changed in CIPHERTEXT when plaintext changed by 1 bit: {changed_bits(c1_affine_x1, c1_affine_x2)}")
    print()
    print("=" * 80)
    
    print("\nSUMMARY:")
    print("-" * 80)
    print("Key sensitivity (how much ciphertext changes when key changes by 4 bits):")
    print(f"  OTP:    {changed_bits(c1_otp, c2_otp)} bits changed in ciphertext")
    print(f"  AFFINE: {changed_bits(c1_affine, c2_affine)} bits changed in ciphertext")
    print()
    print("Plaintext sensitivity (how much ciphertext changes when plaintext changes by 1 bit):")
    print(f"  OTP:    {changed_bits(c1_otp_x1, c1_otp_x2)} bits changed in ciphertext")
    print(f"  AFFINE: {changed_bits(c1_affine_x1, c1_affine_x2)} bits changed in ciphertext")
    print()
    print("Good encryption should change MANY bits (avalanche effect)")
    print("=" * 80)