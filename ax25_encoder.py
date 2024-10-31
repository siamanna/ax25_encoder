#!/usr/bin/env python3
"""
ax25_encoder.py

This script encodes an AX.25 frame with the provided source address,
destination address, and payload. It performs bit stuffing, NRZI encoding,
and scrambling according to the AX.25 and G3RUH 9600 baud FSK standards.
"""

def encode_ax25_address(callsign, ssid_byte, last=False):
    """
    Encodes an AX.25 address field from a callsign and SSID byte.

    Parameters:
        callsign (str): Callsign (up to 6 characters).
        ssid_byte (int): SSID byte (full byte as per AX.25 specification).
        last (bool): True if this is the last address field (sets the extension bit).

    Returns:
        list: A list of 7 bytes representing the encoded address field.
    """
    callsign = callsign.upper().ljust(6)
    address = []
    for c in callsign:
        address.append(ord(c) << 1)
    # Ensure the extension bit is set correctly
    if last:
        ssid_byte |= 0x01  # Set the LSB if this is the last address
    else:
        ssid_byte &= 0xFE  # Clear the LSB if not the last address
    address.append(ssid_byte)
    return address

def compute_crc(data_bytes):
    """
    Computes the CRC-16-CCITT checksum for the given data.

    Parameters:
        data_bytes (list): A list of data bytes.

    Returns:
        int: The computed CRC value.
    """
    shift_register = 0xFFFF
    for byte in data_bytes:
        for i in range(8):  # For each bit (LSB first)
            bit = (byte >> i) & 0x01
            lsb = shift_register & 0x0001
            shift_register >>= 1
            if lsb ^ bit:
                shift_register ^= 0x8408
    return shift_register ^ 0xFFFF

def frame_to_bits(frame_bytes):
    """
    Converts a list of bytes into a list of bits (LSB first per byte).

    Parameters:
        frame_bytes (list): A list of bytes.

    Returns:
        list: A list of bits.
    """
    bits = []
    for byte in frame_bytes:
        for i in range(8):  # 8 bits per byte
            bits.append((byte >> i) & 0x01)  # LSB first
    return bits

def bit_stuff(bits):
    """
    Performs bit stuffing on the input bit stream.

    Parameters:
        bits (list): A list of bits.

    Returns:
        list: A list of bits after bit stuffing.
    """
    stuffed_bits = []
    consecutive_ones = 0
    for bit in bits:
        stuffed_bits.append(bit)
        if bit == 1:
            consecutive_ones += 1
            if consecutive_ones == 5:
                stuffed_bits.append(0)
                consecutive_ones = 0
        else:
            consecutive_ones = 0
    return stuffed_bits

def scramble(bits):
    """
    Scrambles the input bit stream using the G3RUH scrambling algorithm.

    Parameters:
        bits (list): A list of bits.

    Returns:
        list: A list of scrambled bits.
    """
    shift_register = 0x1FF  # Initialize to all ones (as per G3RUH standard)
    scrambled_bits = []
    for bit in bits:
        feedback = ((shift_register >> 12) ^ (shift_register >> 17)) & 0x01
        scrambled_bit = bit ^ feedback
        scrambled_bits.append(scrambled_bit)
        shift_register = ((shift_register << 1) | scrambled_bit) & 0x1FFFF  # 17-bit shift register
    return scrambled_bits

def nrzi_encode(bits):
    """
    Performs NRZI encoding on the input bit stream.

    Parameters:
        bits (list): A list of bits.

    Returns:
        list: A list of NRZI-encoded bits.
    """
    nrzi_bits = []
    last_bit = 1  # NRZI starts with a 'mark' (logic 1)
    for bit in bits:
        if bit == 0:
            last_bit ^= 1  # Transition
        # If bit is 1, no transition
        nrzi_bits.append(last_bit)
    return nrzi_bits

def bits_to_bytes(bits):
    """
    Converts a list of bits into a list of bytes (LSB first per byte).

    Parameters:
        bits (list): A list of bits.

    Returns:
        list: A list of bytes.
    """
    bytes_list = []
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= bits[i + j] << j
        bytes_list.append(byte)
    return bytes_list

def prepare_ax25_frame(dest_callsign, src_callsign, payload):
    """
    Prepares the AX.25 frame with the given addresses and payload.

    Parameters:
        dest_callsign (str): Destination callsign.
        src_callsign (str): Source callsign.
        payload (str): Payload data.

    Returns:
        list: A list of bytes representing the AX.25 frame.
    """
    # Fixed SSID bytes
    dest_ssid_byte = 0xE1  # Destination SSID byte (fixed)
    src_ssid_byte = 0xE0   # Source SSID byte (fixed)

    # Encode addresses
    dest_address = encode_ax25_address(dest_callsign, dest_ssid_byte)
    src_address = encode_ax25_address(src_callsign, src_ssid_byte, last=True)

    # Header: destination address + source address + control + PID
    header = dest_address + src_address + [0x03, 0xF0]

    # Convert payload to bytes
    if isinstance(payload, str):
        payload_bytes = list(payload.encode('ascii'))
    else:
        payload_bytes = list(payload)

    # Build frame without FCS
    frame = header + payload_bytes

    # Compute CRC over frame[1:] (excluding the starting flag)
    crc = compute_crc(frame[1:])

    # Append FCS (LSB first)
    frame += [crc & 0xFF, (crc >> 8) & 0xFF]

    return frame

def main():
    """
    Main function to get user input and encode the AX.25 frame.
    """
    print("AX.25 Frame Encoder")
    print("-------------------")
    # Get user input for addresses and payload
    dest_callsign = input("Enter destination callsign: ").strip()
    src_callsign = input("Enter source callsign: ").strip()
    payload = input("Enter payload: ").strip()

    # Prepare the frame
    frame = prepare_ax25_frame(dest_callsign, src_callsign, payload)

    # Convert frame to bits
    bits = frame_to_bits(frame)

    # Perform bit stuffing
    stuffed_bits = bit_stuff(bits)

    # NRZI encoding
    nrzi_bits = nrzi_encode(stuffed_bits)

    # Scramble NRZI bits
    scrambled_bits = scramble(nrzi_bits)

    # Convert scrambled bits to bytes
    scrambled_bytes = bits_to_bytes(scrambled_bits)

    # Output the encoded frame
    print("\nEncoded AX.25 Frame (NRZI encoded, then scrambled):")
    print("Bit stream:")
    print(''.join(str(bit) for bit in scrambled_bits))
    print("\nHexadecimal representation:")
    print(' '.join(f'{byte:02X}' for byte in scrambled_bytes))

if __name__ == "__main__":
    main()
