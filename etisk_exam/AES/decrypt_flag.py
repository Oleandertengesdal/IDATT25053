from chall import AESCipher

with open('encrypted_flag.txt', 'r') as f:
    encrypted_flag = f.read().strip()

print(f"Encrypted flag: {encrypted_flag}")
print(f"Length: {len(encrypted_flag)}")

course_code = "IIK3100"
print(f"\nBase course code: {course_code} (length: {len(course_code)})")

possible_keys = []

base_variations = [
    course_code              # IIK3100
]

# For each base variation, repeat with odd rotations to get exactly 13 chars
for base in base_variations:
    # Calculate how many times we need to repeat to get at least 13 chars
    times_needed = (13 // len(base)) + 1
    
    # Try odd numbers of repetitions
    for rotations in [1, 3, 5, 7, 9]:
        # Repeat and truncate to exactly 13 characters
        key = (base * rotations)[:13]
        if len(key) == 13 and key not in possible_keys:
            possible_keys.append(key)
            print(f"Candidate: '{key}' (base: '{base}', rotations: {rotations})")

# Add Caesar cipher rotations (ROT-n)
def rotate_char(c, n):
    if c.isalpha():
        base = ord('A') if c.isupper() else ord('a')
        return chr((ord(c) - base + n) % 26 + base)
    return c

def rotate_string(s, n):
    return ''.join(rotate_char(c, n) for c in s)

# Try ROT-n variations (odd numbers)
print("\nAdding ROT-n variations (odd rotations)...")
for base in [course_code, course_code.lower()]:
    for rot in [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25]:
        rotated = rotate_string(base, rot)
        key = (rotated * 3)[:13]
        if len(key) == 13 and key not in possible_keys:
            possible_keys.append(key)
            print(f"Candidate ROT{rot}: '{key}' (from '{base}')")

print(f"\nTotal keys to try: {len(possible_keys)}")
print("=" * 60)

# Try each key
for i, key in enumerate(possible_keys, 1):
    try:
        cipher = AESCipher(key)
        decrypted = cipher.decrypt(encrypted_flag)
        print(f"\n{'='*60}")
        print(f"✓ SUCCESS with key #{i}: '{key}'")
        print(f"{'='*60}")
        print(f"Decrypted flag: {decrypted}")
        print(f"{'='*60}")
        break
    except Exception as e:
        print(f"✗ Key #{i} failed: '{key}' - {type(e).__name__}: {str(e)[:50]}")

else:
    print("\n❌ No valid key found. Try different variations of the course code.")
