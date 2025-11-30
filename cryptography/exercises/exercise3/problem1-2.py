K = [1, 0, 0, 0]


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


state = [int(bit) for bit in K]
initial_state = state.copy()

sequence = [state.copy()]
for i in range(100):
    # Compute next bit using feedback function
    next_bit = lfsr_type_a(state)
    
    # Shift register: remove first bit, append new bit
    state = state[1:] + [next_bit]
    if state == initial_state:
        period = i + 1
        break
    sequence.append(state.copy())
if 'period' in locals():
    print(f"Period for LFSR Type A with key {K}: {period}")
else:
    print(f"No period found within 100 iterations for LFSR Type A with key {K}")    
print("Generated sequence:")
for i, state in enumerate(sequence):
    print(f"  {i:2d}: {state}")

