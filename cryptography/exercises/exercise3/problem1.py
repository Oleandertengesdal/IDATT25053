"""
LFSR (Linear Feedback Shift Register) Period Analysis

This script analyzes the period of different LFSR configurations
with various initial keys.

Exercise 1:
a) LFSR: z[i+4] = z[i] + z[i+1] + z[i+2] + z[i+3] (mod 2)
b) LFSR: z[i+4] = z[i] + z[i+3] (mod 2)
"""


def lfsr_type_a(state):
    """
    LFSR Type A: z[i+4] = z[i] + z[i+1] + z[i+2] + z[i+3] (mod 2)
    
    Args:
        state: List of 4 bits [z[i], z[i+1], z[i+2], z[i+3]]
        
    Returns:
        Next bit z[i+4]
    """
    # XOR all four bits together (addition mod 2)
    return (state[0] + state[1] + state[2] + state[3]) % 2


def lfsr_type_b(state):
    """
    LFSR Type B: z[i+4] = z[i] + z[i+3] (mod 2)
    
    Args:
        state: List of 4 bits [z[i], z[i+1], z[i+2], z[i+3]]
        
    Returns:
        Next bit z[i+4]
    """
    # XOR first and last bit (addition mod 2)
    return (state[0] + state[3]) % 2


def run_lfsr(initial_key, feedback_function, max_iterations=100):
    """
    Run LFSR and determine its period.
    
    Args:
        initial_key: String of bits (e.g., "1000")
        feedback_function: Function that computes next bit
        max_iterations: Maximum iterations to prevent infinite loops
        
    Returns:
        Tuple of (period, sequence)
    """
    # Convert string key to list of integers
    state = [int(bit) for bit in initial_key]
    initial_state = state.copy()
    
    sequence = [state.copy()]
    
    for i in range(max_iterations):
        # Compute next bit using feedback function
        next_bit = feedback_function(state)
        
        # Shift register: remove first bit, append new bit
        state = state[1:] + [next_bit]
        
        # Check if we've returned to initial state
        if state == initial_state:
            period = i + 1
            return period, sequence
        
        sequence.append(state.copy())
    
    # If we didn't find a period, return -1
    return -1, sequence


def state_to_string(state):
    """Convert state list to string for display."""
    return ''.join(map(str, state))


def analyze_lfsr(key, lfsr_type, feedback_function):
    """
    Analyze LFSR with given key and display results.
    
    Args:
        key: Initial key as string (e.g., "1000")
        lfsr_type: Name of LFSR type (e.g., "Type A")
        feedback_function: Function to compute next bit
    """
    print(f"\n{'='*70}")
    print(f"{lfsr_type}: Key = {key}")
    print('='*70)
    
    period, sequence = run_lfsr(key, feedback_function)
    
    if period == -1:
        print(f"⚠ No period found within {len(sequence)} iterations")
    else:
        print(f"✓ Period: {period}")
        print(f"\nSequence (first {min(20, len(sequence))} states):")
        
        for i, state in enumerate(sequence[:20]):
            state_str = state_to_string(state)
            if i == 0:
                print(f"  {i:2d}: {state_str} ← Initial state")
            elif i == period:
                print(f"  {i:2d}: {state_str} ← Returns to initial (period = {period})")
                break
            else:
                print(f"  {i:2d}: {state_str}")
        
        if len(sequence) > 20 and period > 20:
            print(f"  ... ({period - 20} more states)")
            print(f"  {period:2d}: {state_to_string(sequence[0])} ← Returns to initial")
        
        # Show bit stream output
        print(f"\nBit stream output (first 30 bits from leftmost position):")
        bit_stream = ''.join(str(state[0]) for state in sequence[:30])
        print(f"  {bit_stream}")
        
        if period > 0:
            print(f"\nPeriod analysis:")
            print(f"  - The sequence repeats every {period} steps")
            print(f"  - Maximum possible period for 4-bit LFSR: 2^4 - 1 = 15")
            if period == 15:
                print(f"  - ✓ This is a MAXIMAL-LENGTH LFSR (optimal)")
            elif period < 15:
                print(f"  - This LFSR has a shorter period ({period} < 15)")


def main():
    """Main function to run all LFSR analyses."""
    print("="*70)
    print("LFSR PERIOD ANALYSIS")
    print("="*70)
    
    # Define keys to test
    keys = ["1000", "0011", "1111"]
    
    print("\n" + "="*70)
    print("PART A: LFSR z[i+4] = z[i] + z[i+1] + z[i+2] + z[i+3] (mod 2)")
    print("="*70)
    
    results_a = []
    for key in keys:
        analyze_lfsr(key, f"LFSR-A", lfsr_type_a)
        period, _ = run_lfsr(key, lfsr_type_a)
        results_a.append((key, period))
    
    print("\n" + "="*70)
    print("PART B: LFSR z[i+4] = z[i] + z[i+3] (mod 2)")
    print("="*70)
    
    results_b = []
    for key in keys:
        analyze_lfsr(key, f"LFSR-B", lfsr_type_b)
        period, _ = run_lfsr(key, lfsr_type_b)
        results_b.append((key, period))
    
    # Summary table
    print("\n" + "="*70)
    print("SUMMARY OF RESULTS")
    print("="*70)
    
    print("\nPart A: z[i+4] = z[i] + z[i+1] + z[i+2] + z[i+3] (mod 2)")
    print("-"*70)
    print(f"{'Key':<10} {'Period':<10} {'Type':<20}")
    print("-"*70)
    for key, period in results_a:
        period_type = "Maximal-length" if period == 15 else "Shorter period"
        print(f"{key:<10} {period:<10} {period_type:<20}")
    
    print("\nPart B: z[i+4] = z[i] + z[i+3] (mod 2)")
    print("-"*70)
    print(f"{'Key':<10} {'Period':<10} {'Type':<20}")
    print("-"*70)
    for key, period in results_b:
        period_type = "Maximal-length" if period == 15 else "Shorter period"
        print(f"{key:<10} {period:<10} {period_type:<20}")
    
    print("\n" + "="*70)
    print("NOTES:")
    print("="*70)
    print("• For a 4-bit LFSR, maximum period is 2^4 - 1 = 15")
    print("• Period of 15 means the LFSR is maximal-length (optimal)")
    print("• All-zero state (0000) is not counted (would stay at 0000)")
    print("• XOR operation is equivalent to addition modulo 2")
    print("• Feedback polynomial determines if LFSR is maximal-length")
    print("\nFeedback polynomials:")
    print("  Part A: x^4 + x^3 + x^2 + x + 1")
    print("  Part B: x^4 + x + 1 (primitive polynomial → maximal-length)")
    print("="*70)


if __name__ == "__main__":
    main()