"""
Enigma Machine Simulation (Simplified Educational Model)

This is a SIMPLIFIED simulation of the Enigma I machine for educational purposes.
It demonstrates the core concepts but is not historically accurate in all details.

Components simulated:
- 3 rotors (with turnover notches)
- Reflector (UKW-B)
- Plugboard
- Rotor stepping mechanism

EDUCATIONAL PURPOSE ONLY - NOT FOR REAL SECURITY
"""

import string
from typing import List, Tuple, Dict


# Historical rotor wirings (Enigma I)
ROTOR_WIRINGS = {
    'I':   'EKMFLGDQVZNTOWYHXUSPAIBRCJ',
    'II':  'AJDKSIRUXBLHWTMCQGZNPYFVOE',
    'III': 'BDFHJLCPRTXVZNYEIWGAKMUSQO',
    'IV':  'ESOVPZJAYQUIRHXLNFTGKDCMWB',
    'V':   'VZBRGITYUPSDNHLXAWMJQOFECK'
}

# Turnover notches (when rotor steps the next rotor)
ROTOR_NOTCHES = {
    'I':   'Q',
    'II':  'E',
    'III': 'V',
    'IV':  'J',
    'V':   'Z'
}

# Reflector wiring (UKW-B)
REFLECTOR_B = 'YRUHQSLDPXNGOKMIEBFZCWVJAT'

# Alphabet for reference
ALPHABET = string.ascii_uppercase


class EnigmaRotor:
    """Represents a single Enigma rotor."""
    
    def __init__(self, wiring: str, notch: str, ring_setting: int = 0, initial_position: str = 'A'):
        """
        Initialize a rotor.
        
        Args:
            wiring: Letter substitution string (e.g., 'EKMFLGDQVZNTOWYHXUSPAIBRCJ')
            notch: Letter position where rotor causes next rotor to step
            ring_setting: Ring setting (0-25, default 0)
            initial_position: Starting position (A-Z, default 'A')
        """
        self.wiring = wiring
        self.notch = notch
        self.ring_setting = ring_setting
        self.position = ALPHABET.index(initial_position)
        
    def step(self) -> bool:
        """
        Step the rotor by one position.
        
        Returns:
            True if at notch position (causes next rotor to step)
        """
        at_notch = ALPHABET[self.position] == self.notch
        self.position = (self.position + 1) % 26
        return at_notch
    
    def forward(self, letter_index: int) -> int:
        """
        Pass signal through rotor (right to left).
        
        Args:
            letter_index: Input letter (0-25)
            
        Returns:
            Output letter (0-25)
        """
        # Adjust for rotor position and ring setting
        shift = self.position - self.ring_setting
        
        # Entry
        index = (letter_index + shift) % 26
        
        # Through wiring
        letter = ALPHABET[index]
        output_letter = self.wiring[index]
        output_index = ALPHABET.index(output_letter)
        
        # Exit
        result = (output_index - shift) % 26
        
        return result
    
    def backward(self, letter_index: int) -> int:
        """
        Pass signal through rotor (left to right, after reflector).
        
        Args:
            letter_index: Input letter (0-25)
            
        Returns:
            Output letter (0-25)
        """
        # Adjust for rotor position and ring setting
        shift = self.position - self.ring_setting
        
        # Entry
        index = (letter_index + shift) % 26
        
        # Through wiring (reverse lookup)
        letter = ALPHABET[index]
        # Find position of this letter in wiring
        for i, c in enumerate(self.wiring):
            if ALPHABET[i] == letter:
                output_index = i
                break
        
        # Exit
        result = (output_index - shift) % 26
        
        return result
    
    def get_position(self) -> str:
        """Get current rotor position as letter."""
        return ALPHABET[self.position]


class EnigmaReflector:
    """Represents an Enigma reflector."""
    
    def __init__(self, wiring: str):
        """
        Initialize reflector.
        
        Args:
            wiring: Reflection pairs (e.g., 'YRUHQSLDPXNGOKMIEBFZCWVJAT')
        """
        self.wiring = wiring
    
    def reflect(self, letter_index: int) -> int:
        """
        Reflect the signal.
        
        Args:
            letter_index: Input letter (0-25)
            
        Returns:
            Reflected letter (0-25)
        """
        letter = ALPHABET[letter_index]
        reflected = self.wiring[letter_index]
        return ALPHABET.index(reflected)


class EnigmaPlugboard:
    """Represents an Enigma plugboard (Steckerbrett)."""
    
    def __init__(self, pairs: List[Tuple[str, str]] = None):
        """
        Initialize plugboard.
        
        Args:
            pairs: List of letter pairs to swap (e.g., [('A', 'B'), ('C', 'D')])
        """
        self.mapping = {}
        
        if pairs:
            for a, b in pairs:
                self.mapping[a] = b
                self.mapping[b] = a
    
    def swap(self, letter: str) -> str:
        """
        Swap letter if in plugboard mapping.
        
        Args:
            letter: Input letter
            
        Returns:
            Swapped letter (or same if not in mapping)
        """
        return self.mapping.get(letter, letter)


class EnigmaMachine:
    """Simplified Enigma I machine simulation."""
    
    def __init__(self, 
                 rotor_types: Tuple[str, str, str],
                 rotor_positions: Tuple[str, str, str],
                 ring_settings: Tuple[int, int, int] = (0, 0, 0),
                 plugboard_pairs: List[Tuple[str, str]] = None):
        """
        Initialize Enigma machine.
        
        Args:
            rotor_types: Rotor types (e.g., ('I', 'II', 'III'))
            rotor_positions: Initial rotor positions (e.g., ('A', 'A', 'A'))
            ring_settings: Ring settings (0-25 for each rotor)
            plugboard_pairs: Plugboard connections
            
        Example:
            enigma = EnigmaMachine(
                rotor_types=('I', 'II', 'III'),
                rotor_positions=('Q', 'E', 'V'),
                ring_settings=(0, 0, 0),
                plugboard_pairs=[('A', 'B'), ('C', 'D')]
            )
        """
        # Create rotors (right to left: fast, medium, slow)
        self.rotors = [
            EnigmaRotor(ROTOR_WIRINGS[rotor_types[2]], ROTOR_NOTCHES[rotor_types[2]], 
                       ring_settings[2], rotor_positions[2]),  # Right (fast)
            EnigmaRotor(ROTOR_WIRINGS[rotor_types[1]], ROTOR_NOTCHES[rotor_types[1]], 
                       ring_settings[1], rotor_positions[1]),  # Middle
            EnigmaRotor(ROTOR_WIRINGS[rotor_types[0]], ROTOR_NOTCHES[rotor_types[0]], 
                       ring_settings[0], rotor_positions[0])   # Left (slow)
        ]
        
        self.reflector = EnigmaReflector(REFLECTOR_B)
        self.plugboard = EnigmaPlugboard(plugboard_pairs)
        
    def step_rotors(self):
        """
        Step rotors according to Enigma stepping mechanism.
        
        Enigma stepping rules:
        1. Right rotor always steps
        2. If right rotor is at notch, middle rotor steps
        3. If middle rotor is at notch, middle AND left rotor step (double-stepping)
        """
        # Check if middle rotor is at notch (double-stepping)
        middle_at_notch = self.rotors[1].get_position() == self.rotors[1].notch
        
        if middle_at_notch:
            # Double-stepping: middle and left rotors step
            self.rotors[1].step()
            self.rotors[2].step()
        else:
            # Check if right rotor causes middle to step
            right_at_notch = self.rotors[0].get_position() == self.rotors[0].notch
            if right_at_notch:
                self.rotors[1].step()
        
        # Right rotor always steps
        self.rotors[0].step()
    
    def encrypt_letter(self, letter: str) -> str:
        """
        Encrypt/decrypt a single letter.
        
        Process:
        1. Step rotors
        2. Through plugboard
        3. Through rotors (right to left)
        4. Through reflector
        5. Back through rotors (left to right)
        6. Through plugboard again
        
        Args:
            letter: Single letter to encrypt (A-Z)
            
        Returns:
            Encrypted letter
        """
        if letter not in ALPHABET:
            return letter  # Return non-letters unchanged
        
        # Step rotors BEFORE encryption
        self.step_rotors()
        
        # Through plugboard
        letter = self.plugboard.swap(letter)
        current = ALPHABET.index(letter)
        
        # Through rotors (right to left)
        for rotor in self.rotors:
            current = rotor.forward(current)
        
        # Through reflector
        current = self.reflector.reflect(current)
        
        # Back through rotors (left to right)
        for rotor in reversed(self.rotors):
            current = rotor.backward(current)
        
        # Through plugboard again
        result = ALPHABET[current]
        result = self.plugboard.swap(result)
        
        return result
    
    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt/decrypt a message.
        
        Args:
            plaintext: Text to encrypt
            
        Returns:
            Encrypted text
        """
        result = []
        
        for char in plaintext.upper():
            if char in ALPHABET:
                result.append(self.encrypt_letter(char))
            else:
                result.append(char)
        
        return ''.join(result)
    
    def get_rotor_positions(self) -> str:
        """Get current rotor positions."""
        return ''.join(rotor.get_position() for rotor in reversed(self.rotors))


def demonstrate_enigma():
    """Interactive demonstration of Enigma machine."""
    print("=" * 70)
    print("ENIGMA MACHINE SIMULATION")
    print("=" * 70)
    
    # Example 1: Basic encryption/decryption
    print("\n[EXAMPLE 1] Basic Encryption/Decryption")
    print("-" * 70)
    
    # Configure machine
    rotor_types = ('I', 'II', 'III')
    rotor_positions = ('A', 'A', 'A')
    plugboard_pairs = [('A', 'B'), ('C', 'D'), ('E', 'F')]
    
    print(f"Configuration:")
    print(f"  Rotors: {rotor_types}")
    print(f"  Initial positions: {rotor_positions}")
    print(f"  Plugboard: {plugboard_pairs}")
    
    # Encrypt
    enigma1 = EnigmaMachine(rotor_types, rotor_positions, plugboard_pairs=plugboard_pairs)
    plaintext = "HELLO WORLD"
    ciphertext = enigma1.encrypt(plaintext)
    
    print(f"\nPlaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Final rotor positions: {enigma1.get_rotor_positions()}")
    
    # Decrypt (reset machine to same initial state)
    enigma2 = EnigmaMachine(rotor_types, rotor_positions, plugboard_pairs=plugboard_pairs)
    decrypted = enigma2.encrypt(ciphertext)  # Enigma is symmetric!
    
    print(f"Decrypted:  {decrypted}")
    print(f"✓ Correct:  {plaintext == decrypted}")
    
    # Example 2: Rotor stepping demonstration
    print("\n[EXAMPLE 2] Rotor Stepping Mechanism")
    print("-" * 70)
    
    enigma = EnigmaMachine(('I', 'II', 'III'), ('A', 'A', 'U'))
    
    print("Encrypting 'AAAAA...' to show rotor stepping:")
    print(f"Initial positions: {enigma.get_rotor_positions()}")
    
    for i in range(10):
        encrypted = enigma.encrypt_letter('A')
        print(f"  Step {i+1}: Position={enigma.get_rotor_positions()}, A→{encrypted}")
    
    # Example 3: Symmetry property
    print("\n[EXAMPLE 3] Enigma Symmetry")
    print("-" * 70)
    
    enigma = EnigmaMachine(('I', 'II', 'III'), ('A', 'A', 'A'))
    
    print("If A encrypts to X, then X encrypts to A:")
    
    # Encrypt A
    enigma1 = EnigmaMachine(('I', 'II', 'III'), ('A', 'A', 'A'))
    result1 = enigma1.encrypt_letter('A')
    print(f"  A → {result1}")
    
    # Encrypt the result
    enigma2 = EnigmaMachine(('I', 'II', 'III'), ('A', 'A', 'A'))
    result2 = enigma2.encrypt_letter(result1)
    print(f"  {result1} → {result2}")
    
    print(f"✓ Symmetric: {result2 == 'A'}")
    
    # Example 4: Letter never encrypts to itself
    print("\n[EXAMPLE 4] Enigma's Fatal Flaw: No Letter Maps to Itself")
    print("-" * 70)
    
    enigma = EnigmaMachine(('I', 'II', 'III'), ('A', 'A', 'A'))
    
    print("Testing all 26 letters:")
    self_encryptions = []
    
    for letter in ALPHABET:
        enigma_test = EnigmaMachine(('I', 'II', 'III'), ('A', 'A', 'A'))
        encrypted = enigma_test.encrypt_letter(letter)
        if letter == encrypted:
            self_encryptions.append(letter)
        print(f"  {letter} → {encrypted}", end="")
        if letter == encrypted:
            print(" ⚠ SAME!", end="")
        print()
    
    print(f"\nLetters that encrypt to themselves: {self_encryptions if self_encryptions else 'NONE'}")
    print(f"✓ This flaw helped Alan Turing break Enigma!")
    
    # Example 5: Different settings produce different encryption
    print("\n[EXAMPLE 5] Importance of Settings")
    print("-" * 70)
    
    message = "ATTACK AT DAWN"
    
    configs = [
        (('I', 'II', 'III'), ('A', 'A', 'A'), []),
        (('I', 'II', 'III'), ('Q', 'E', 'V'), []),
        (('III', 'II', 'I'), ('A', 'A', 'A'), []),
        (('I', 'II', 'III'), ('A', 'A', 'A'), [('A', 'Z'), ('B', 'Y')])
    ]
    
    print(f"Message: {message}\n")
    
    for i, (rotors, positions, plugboard) in enumerate(configs, 1):
        enigma = EnigmaMachine(rotors, positions, plugboard_pairs=plugboard)
        encrypted = enigma.encrypt(message)
        print(f"Config {i}: Rotors={rotors}, Pos={positions}, Plugs={len(plugboard)}")
        print(f"  Encrypted: {encrypted}\n")
    
    # Example 6: Security lessons
    print("\n[EXAMPLE 6] Why Enigma Was Broken")
    print("-" * 70)
    print("Key weaknesses that led to Enigma being broken:")
    print("1. ⚠ Letter never encrypts to itself (due to reflector)")
    print("2. ⚠ Predictable message formats (e.g., 'WEATHER REPORT')")
    print("3. ⚠ Operator errors (using weak initial settings)")
    print("4. ⚠ Captured codebooks and machines")
    print("5. ⚠ Limited keyspace (compared to modern standards)")
    print("\nKeyspace: ~150 million million million (10^23)")
    print("Modern AES-256: 2^256 ≈ 10^77 (vastly larger!)")
    print("\n✓ Use modern encryption (AES-256) for real security!")


def calculate_keyspace():
    """Calculate Enigma keyspace."""
    print("\n" + "=" * 70)
    print("ENIGMA KEYSPACE CALCULATION")
    print("=" * 70)
    
    # Rotor selection and order (5 choices for 3 positions)
    rotor_choices = 5 * 4 * 3
    print(f"Rotor selection (5 rotors, choose 3): 5×4×3 = {rotor_choices}")
    
    # Rotor positions (26 positions each)
    rotor_positions = 26 ** 3
    print(f"Initial rotor positions: 26³ = {rotor_positions:,}")
    
    # Ring settings (26 settings each)
    ring_settings = 26 ** 3
    print(f"Ring settings: 26³ = {ring_settings:,}")
    
    # Plugboard (10 pairs from 26 letters)
    # This is approximate: C(26,2) × C(24,2) × ... × C(8,2)
    plugboard = 150_738_274_937_250
    print(f"Plugboard (10 pairs): ≈ {plugboard:,}")
    
    total = rotor_choices * rotor_positions * ring_settings * plugboard
    print(f"\nTotal keyspace: ≈ {total:.2e}")
    print(f"                ≈ 10^23")
    print(f"\nFor comparison:")
    print(f"  DES (56-bit):     2^56 ≈ 7.2 × 10^16")
    print(f"  Enigma:           ≈ 1.5 × 10^20")
    print(f"  AES-128:          2^128 ≈ 3.4 × 10^38")
    print(f"  AES-256:          2^256 ≈ 1.2 × 10^77")


if __name__ == "__main__":
    # Run demonstration
    demonstrate_enigma()
    
    # Calculate keyspace
    calculate_keyspace()
    
    # Interactive mode
    print("\n" + "=" * 70)
    print("INTERACTIVE MODE")
    print("=" * 70)
    
    while True:
        print("\nOptions:")
        print("1. Encrypt/Decrypt a message")
        print("2. Test rotor stepping")
        print("3. Demonstrate symmetry")
        print("4. Exit")
        
        choice = input("\nChoose option (1-4): ").strip()
        
        if choice == '1':
            print("\nEnigma Configuration:")
            rotors_input = input("  Rotor types (e.g., 'I II III'): ").strip().split()
            if len(rotors_input) != 3:
                print("  Error: Need exactly 3 rotors")
                continue
            
            positions_input = input("  Initial positions (e.g., 'A A Z'): ").strip().split()
            if len(positions_input) != 3:
                print("  Error: Need exactly 3 positions")
                continue
            
            plugboard_input = input("  Plugboard pairs (e.g., 'AB CD EF' or leave empty): ").strip()
            plugboard_pairs = []
            if plugboard_input:
                pairs = plugboard_input.split()
                plugboard_pairs = [(p[0], p[1]) for p in pairs if len(p) == 2]
            
            enigma = EnigmaMachine(
                tuple(rotors_input),
                tuple(positions_input),
                plugboard_pairs=plugboard_pairs
            )
            
            message = input("\n  Message to encrypt: ").strip()
            result = enigma.encrypt(message)
            
            print(f"\n  Result: {result}")
            print(f"  Final rotor positions: {enigma.get_rotor_positions()}")
            
        elif choice == '2':
            enigma = EnigmaMachine(('I', 'II', 'III'), ('A', 'A', 'U'))
            steps = int(input("  Number of steps to show (1-26): ").strip() or "10")
            
            print(f"\n  Initial positions: {enigma.get_rotor_positions()}")
            for i in range(steps):
                result = enigma.encrypt_letter('A')
                print(f"  Step {i+1}: {enigma.get_rotor_positions()} - A→{result}")
        
        elif choice == '3':
            enigma1 = EnigmaMachine(('I', 'II', 'III'), ('A', 'A', 'A'))
            enigma2 = EnigmaMachine(('I', 'II', 'III'), ('A', 'A', 'A'))
            
            letter = input("  Enter a letter: ").strip().upper()
            if len(letter) == 1 and letter in ALPHABET:
                result1 = enigma1.encrypt_letter(letter)
                result2 = enigma2.encrypt_letter(result1)
                
                print(f"\n  {letter} → {result1}")
                print(f"  {result1} → {result2}")
                print(f"  Symmetric: {'✓ YES' if result2 == letter else '✗ NO'}")
            else:
                print("  Error: Enter a single letter A-Z")
        
        elif choice == '4':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")
