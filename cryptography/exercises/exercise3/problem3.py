"""
Oppgave 3: CBC-MAC with Caesar Cipher

Use the Caesar cipher, with encryption e3(x) = x + 3 (mod 2^8)
and find the CBC-MAC to the following two messages:
x  = 1101 1111 1010 0001
x' = 0010 1100 0001 1111

CBC-MAC process:
1. Split message into 8-bit blocks
2. Initialize IV = 0
3. For each block:
   - XOR block with previous ciphertext (or IV for first block)
   - Encrypt using e3(x) = (x + 3) mod 256
   - Result becomes previous ciphertext
4. Final ciphertext is the MAC
"""


def bits_to_int(bits):
    """Convert list of bits to integer."""
    return int(''.join(map(str, bits)), 2)


def int_to_bits(n, width=8):
    """Convert integer to list of bits with specified width."""
    return [int(b) for b in format(n, f'0{width}b')]


def caesar_encrypt(byte_value, shift=3):
    """
    Encrypt a byte value using Caesar cipher.
    e3(x) = (x + shift) mod 2^8
    
    Args:
        byte_value: Integer value (0-255)
        shift: Shift amount (default 3)
        
    Returns:
        Encrypted integer value (0-255)
    """
    return (byte_value + shift) % 256


def compute_cbc_mac(message_bits, shift=3):
    """
    Compute CBC-MAC for the given message using Caesar cipher.
    
    Args:
        message_bits: List of bits (length must be multiple of 8)
        shift: Caesar cipher shift amount
        
    Returns:
        MAC as 8-bit integer
    """
    print(f"\nComputing CBC-MAC:")
    print(f"{'='*70}")
    print(f"Message: {''.join(map(str, message_bits))}")
    
    # Split message into 8-bit blocks
    block_size = 8
    blocks = []
    for i in range(0, len(message_bits), block_size):
        block_bits = message_bits[i:i + block_size]
        block_value = bits_to_int(block_bits)
        blocks.append(block_value)
        print(f"Block {i//8 + 1}: {''.join(map(str, block_bits))} = {block_value}")
    
    # Initialize IV = 0
    previous_ciphertext = 0
    print(f"\nInitial IV: {previous_ciphertext}")
    
    # Process each block
    for i, block in enumerate(blocks, 1):
        print(f"\n--- Block {i} ---")
        print(f"  Current block:         {block} = {format(block, '08b')}")
        print(f"  Previous ciphertext:   {previous_ciphertext} = {format(previous_ciphertext, '08b')}")
        
        # XOR with previous ciphertext
        xor_result = block ^ previous_ciphertext
        print(f"  XOR result:            {xor_result} = {format(xor_result, '08b')}")
        
        # Encrypt using Caesar cipher: e3(x) = (x + 3) mod 256
        ciphertext = caesar_encrypt(xor_result, shift)
        print(f"  After e3(x) = x+{shift} mod 256: {ciphertext} = {format(ciphertext, '08b')}")
        
        # Update previous ciphertext
        previous_ciphertext = ciphertext
    
    print(f"\n{'='*70}")
    print(f"✓ CBC-MAC = {previous_ciphertext} = {format(previous_ciphertext, '08b')}")
    print(f"{'='*70}")
    
    return previous_ciphertext


def main():
    """Main function to solve the exercise."""
    
    # Given messages
    x = [1,1,0,1, 1,1,1,1, 1,0,1,0, 0,0,0,1]
    x_prime = [0,0,1,0, 1,1,0,0, 0,0,0,1, 1,1,1,1]
    
    print("="*70)
    print("CBC-MAC WITH CAESAR CIPHER")
    print("="*70)
    print(f"\nEncryption function: e3(x) = (x + 3) mod 2^8")
    print(f"Block size: 8 bits")
    print(f"IV: 0")
    
    # Compute CBC-MAC for x
    print("\n" + "="*70)
    print("MESSAGE x = 1101 1111 1010 0001")
    print("="*70)
    mac_x = compute_cbc_mac(x, shift=3)
    
    # Compute CBC-MAC for x'
    print("\n" + "="*70)
    print("MESSAGE x' = 0010 1100 0001 1111")
    print("="*70)
    mac_x_prime = compute_cbc_mac(x_prime, shift=3)
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    print(f"\nMessage x:  {''.join(map(str, x))}")
    print(f"  Block 1: {format(bits_to_int(x[0:8]), '08b')} = {bits_to_int(x[0:8])}")
    print(f"  Block 2: {format(bits_to_int(x[8:16]), '08b')} = {bits_to_int(x[8:16])}")
    print(f"  CBC-MAC: {format(mac_x, '08b')} = {mac_x}")
    
    print(f"\nMessage x': {''.join(map(str, x_prime))}")
    print(f"  Block 1: {format(bits_to_int(x_prime[0:8]), '08b')} = {bits_to_int(x_prime[0:8])}")
    print(f"  Block 2: {format(bits_to_int(x_prime[8:16]), '08b')} = {bits_to_int(x_prime[8:16])}")
    print(f"  CBC-MAC: {format(mac_x_prime, '08b')} = {mac_x_prime}")
    
    print("\n" + "="*70)


if __name__ == "__main__":
    main()
