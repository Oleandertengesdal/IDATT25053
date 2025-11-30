"""
HMAC with Midsquare Hashing

Exercise 2:
- Key K = 1001
- ipad = 0011
- opad = 0101
- h is midsquare hashing: x^2 (mod 2^8), taking middle 4 binary digits

HMAC formula:
HMAC(K, M) = h((K ⊕ opad) || h((K ⊕ ipad) || M))
"""


def bits_to_int(bits):
    """Convert list of bits to integer."""
    return int(''.join(map(str, bits)), 2)


def int_to_bits(n, width=4):
    """Convert integer to list of bits with specified width."""
    return [int(b) for b in format(n, f'0{width}b')]


def xor_bits(bits1, bits2):
    """XOR two bit arrays."""
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]


def concatenate_bits(bits1, bits2):
    """Concatenate two bit arrays."""
    return bits1 + bits2


def midsquare_hash(bits):
    """
    Midsquare hashing function.
    
    Process:
    1. Convert bits to integer x
    2. Compute x^2
    3. Take result mod 2^8 (keep only 8 bits)
    4. Extract middle 4 bits
    
    Args:
        bits: List of bits
        
    Returns:
        List of 4 bits (middle bits of x^2 mod 2^8)
    """
    # Convert to integer
    x = bits_to_int(bits)
    
    # Square it
    x_squared = x * x
    
    # Take mod 2^8 (256) to get 8-bit result
    result_8bit = x_squared % 256
    
    # Convert to 8-bit binary string
    binary_8bit = format(result_8bit, '08b')
    
    # Extract middle 4 bits (indices 2, 3, 4, 5)
    middle_bits = [int(binary_8bit[i]) for i in range(2, 6)]
    
    return middle_bits


def compute_hmac(key, message, ipad, opad):
    """
    Compute HMAC using midsquare hashing.
    
    HMAC(K, M) = h((K ⊕ opad) || h((K ⊕ ipad) || M))
    
    Args:
        key: Key as list of bits
        message: Message as list of bits
        ipad: Inner padding as list of bits
        opad: Outer padding as list of bits
        
    Returns:
        HMAC as list of 4 bits
    """
    print(f"\nComputing HMAC step by step:")
    print(f"{'='*70}")
    
    # Step 1: K ⊕ ipad
    k_xor_ipad = xor_bits(key, ipad)
    print(f"\nStep 1: K ⊕ ipad")
    print(f"  K:     {''.join(map(str, key))}")
    print(f"  ipad:  {''.join(map(str, ipad))}")
    print(f"  K⊕ipad: {''.join(map(str, k_xor_ipad))} = {bits_to_int(k_xor_ipad)}")
    
    # Step 2: (K ⊕ ipad) || M
    inner_input = concatenate_bits(k_xor_ipad, message)
    print(f"\nStep 2: (K ⊕ ipad) || M")
    print(f"  K⊕ipad: {''.join(map(str, k_xor_ipad))}")
    print(f"  M:      {''.join(map(str, message))}")
    print(f"  Concat: {''.join(map(str, inner_input))} = {bits_to_int(inner_input)}")
    
    # Step 3: h((K ⊕ ipad) || M)
    inner_hash = midsquare_hash(inner_input)
    x = bits_to_int(inner_input)
    x_squared = x * x
    result_8bit = x_squared % 256
    print(f"\nStep 3: h((K ⊕ ipad) || M) - Inner hash")
    print(f"  Input:  {''.join(map(str, inner_input))} = {x}")
    print(f"  x^2:    {x}^2 = {x_squared}")
    print(f"  mod 2^8: {x_squared} mod 256 = {result_8bit}")
    print(f"  8-bit:  {format(result_8bit, '08b')}")
    print(f"  Middle: {''.join(map(str, inner_hash))} = {bits_to_int(inner_hash)}")
    
    # Step 4: K ⊕ opad
    k_xor_opad = xor_bits(key, opad)
    print(f"\nStep 4: K ⊕ opad")
    print(f"  K:     {''.join(map(str, key))}")
    print(f"  opad:  {''.join(map(str, opad))}")
    print(f"  K⊕opad: {''.join(map(str, k_xor_opad))} = {bits_to_int(k_xor_opad)}")
    
    # Step 5: (K ⊕ opad) || h((K ⊕ ipad) || M)
    outer_input = concatenate_bits(k_xor_opad, inner_hash)
    print(f"\nStep 5: (K ⊕ opad) || h((K ⊕ ipad) || M)")
    print(f"  K⊕opad:     {''.join(map(str, k_xor_opad))}")
    print(f"  Inner hash: {''.join(map(str, inner_hash))}")
    print(f"  Concat:     {''.join(map(str, outer_input))} = {bits_to_int(outer_input)}")
    
    # Step 6: h((K ⊕ opad) || h((K ⊕ ipad) || M))
    hmac = midsquare_hash(outer_input)
    y = bits_to_int(outer_input)
    y_squared = y * y
    result_8bit_outer = y_squared % 256
    print(f"\nStep 6: h((K ⊕ opad) || h((K ⊕ ipad) || M)) - Outer hash")
    print(f"  Input:  {''.join(map(str, outer_input))} = {y}")
    print(f"  y^2:    {y}^2 = {y_squared}")
    print(f"  mod 2^8: {y_squared} mod 256 = {result_8bit_outer}")
    print(f"  8-bit:  {format(result_8bit_outer, '08b')}")
    print(f"  Middle: {''.join(map(str, hmac))} = {bits_to_int(hmac)}")
    
    print(f"\n{'='*70}")
    print(f"✓ HMAC = {''.join(map(str, hmac))}")
    print(f"{'='*70}")
    
    return hmac


def verify_hmac(key, message, received_hmac, ipad, opad):
    """
    Verify if received HMAC is authentic.
    
    Args:
        key: Key as list of bits
        message: Message as list of bits
        received_hmac: Received HMAC as list of bits
        ipad: Inner padding
        opad: Outer padding
        
    Returns:
        Boolean indicating if HMAC is valid
    """
    print(f"\nVerifying HMAC:")
    print(f"{'='*70}")
    print(f"Message:       {''.join(map(str, message))}")
    print(f"Received HMAC: {''.join(map(str, received_hmac))}")
    
    # Compute expected HMAC
    computed_hmac = compute_hmac(key, message, ipad, opad)
    
    # Compare
    is_valid = (computed_hmac == received_hmac)
    
    print(f"\n{'='*70}")
    print(f"Computed HMAC: {''.join(map(str, computed_hmac))}")
    print(f"Received HMAC: {''.join(map(str, received_hmac))}")
    print(f"Match: {is_valid}")
    
    if is_valid:
        print(f"✓ HMAC is VALID - Message is authentic!")
    else:
        print(f"✗ HMAC is INVALID - Message may be tampered or incorrect!")
    print(f"{'='*70}")
    
    return is_valid


def main():
    """Main function to solve the exercise."""
    
    # Given values
    K = [1, 0, 0, 1]
    ipad = [0, 0, 1, 1]
    opad = [0, 1, 0, 1]
    
    print("="*70)
    print("HMAC WITH MIDSQUARE HASHING")
    print("="*70)
    print(f"\nGiven parameters:")
    print(f"  Key (K):  {''.join(map(str, K))} = {bits_to_int(K)}")
    print(f"  ipad:     {''.join(map(str, ipad))} = {bits_to_int(ipad)}")
    print(f"  opad:     {''.join(map(str, opad))} = {bits_to_int(opad)}")
    print(f"\nHash function: Midsquare (x^2 mod 2^8, middle 4 bits)")
    
    # Part a) Find HMAC for message 0110
    print("\n" + "="*70)
    print("PART A: Find HMAC for message 0110")
    print("="*70)
    
    message_a = [0, 1, 1, 0]
    hmac_a = compute_hmac(K, message_a, ipad, opad)
    
    print(f"\n✓ ANSWER (a): HMAC for message 0110 is {''.join(map(str, hmac_a))}")
    
    # Part b) Verify message 0111 with HMAC 0100
    print("\n" + "="*70)
    print("PART B: Verify message 0111 with HMAC 0100")
    print("="*70)
    
    message_b = [0, 1, 1, 1]
    received_hmac_b = [0, 1, 0, 0]
    
    is_authentic = verify_hmac(K, message_b, received_hmac_b, ipad, opad)
    
    print(f"\n✓ ANSWER (b): The message {'IS' if is_authentic else 'IS NOT'} authentic.")
    if not is_authentic:
        print(f"  There is NO reason to believe the message is authentic.")
        print(f"  The HMAC does not match - message may be tampered!")
    else:
        print(f"  There IS reason to believe the message is authentic.")
        print(f"  The HMAC matches correctly.")
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"\nPart a) Message: 0110 → HMAC: {''.join(map(str, hmac_a))}")
    print(f"Part b) Message: 0111, Received HMAC: 0100 → {'VALID' if is_authentic else 'INVALID'}")
    print("\n" + "="*70)


if __name__ == "__main__":
    main()
