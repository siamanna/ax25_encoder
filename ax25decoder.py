# ax25decoder.py

class AX25Decoder:
    def __init__(self):
        pass

    def decode(self, encoded_frame):
        # Convert bytes to bits
        bits = self.bits_from_bytes(encoded_frame)

        # Remove flags (assuming flags are 0x7E)
        flag_bits = self.bits_from_bytes([0x7E])
        if bits[:len(flag_bits)] != flag_bits or bits[-len(flag_bits):] != flag_bits:
            print("Error: Flags not found")
            return None
        bits = bits[len(flag_bits):-len(flag_bits)]

        # Bit unstuffing
        unstuffed_bits = self.bit_unstuff(bits)

        # NRZI decode
        nrzi_decoded_bits = self.nrzi_decode(unstuffed_bits)

        # Descramble
        descrambled_bits = self.descramble(nrzi_decoded_bits)

        # Convert bits to bytes
        frame = self.bytes_from_bits(descrambled_bits)

        # Verify CRC
        if not self.verify_crc(frame):
            print("Error: CRC check failed")
            return None

        # Remove CRC
        frame = frame[:-2]

        # Parse frame
        return self.parse_frame(frame)

    def bits_from_bytes(self, data):
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> i) & 0x01)
        return bits

    def bytes_from_bits(self, bits):
        data = []
        byte = 0
        for i, bit in enumerate(bits):
            byte |= (bit << (i % 8))
            if (i % 8) == 7:
                data.append(byte)
                byte = 0
        if (len(bits) % 8) != 0:
            data.append(byte)
        return data

    def bit_unstuff(self, bits):
        unstuffed_bits = []
        consecutive_ones = 0
        i = 0
        while i < len(bits):
            bit = bits[i]
            unstuffed_bits.append(bit)
            if bit == 1:
                consecutive_ones += 1
                if consecutive_ones == 5:
                    # Skip the stuffed zero
                    i += 1
                    consecutive_ones = 0
            else:
                consecutive_ones = 0
            i += 1
        return unstuffed_bits

    def nrzi_decode(self, bits):
        decoded_bits = []
        last_nrzi_bit = 1  # NRZI starts with mark
        for bit in bits:
            if bit == last_nrzi_bit:
                decoded_bits.append(0)
            else:
                decoded_bits.append(1)
            last_nrzi_bit = bit
        return decoded_bits

    def descramble(self, bits):
        sr = [0]*17  # Shift register initialized with zeros
        descrambled_bits = []
        for bit in bits:
            # Scrambler polynomial: x^17 + x^12 + 1
            feedback = sr[11] ^ sr[16]
            descrambled_bit = bit ^ feedback
            descrambled_bits.append(descrambled_bit)
            # Shift register
            sr = [descrambled_bit] + sr[:-1]
        return descrambled_bits

    def compute_crc(self, frame):
        crc = 0xFFFF
        for byte in frame:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0x8408  # 0x8408 is the reverse polynomial of 0x1021
                else:
                    crc >>= 1
        return crc ^ 0xFFFF

    def verify_crc(self, frame):
        # Extract the received CRC from the last two bytes (LSB first)
        received_crc = frame[-2] | (frame[-1] << 8)
        # Compute the CRC over the frame excluding the last two bytes (the CRC)
        computed_crc = self.compute_crc(frame[:-2])
        return computed_crc == received_crc

    def parse_frame(self, frame):
        result = {}

        # Addresses are 7 bytes each
        if len(frame) < 16:
            print("Error: Frame too short")
            return None

        dest_address = frame[:7]
        src_address = frame[7:14]

        # Control and PID fields
        control = frame[14]
        pid = frame[15]

        # Information field
        info = frame[16:]

        # Decode addresses
        result['dest_callsign'] = ''.join([chr((b >> 1) & 0x7F) for b in dest_address[:6]]).strip()
        result['dest_ssid'] = (dest_address[6] >> 1) & 0x0F

        result['src_callsign'] = ''.join([chr((b >> 1) & 0x7F) for b in src_address[:6]]).strip()
        result['src_ssid'] = (src_address[6] >> 1) & 0x0F

        result['control'] = control
        result['pid'] = pid
        result['info'] = ''.join([chr(b) for b in info])

        return result

if __name__ == "__main__":
    # Example usage:
    import argparse
    import re

    parser = argparse.ArgumentParser(description='AX.25 Decoder')
    parser.add_argument('--frame', type=str, required=True, help='Encoded frame in hex format (e.g., "7E FF FF ...")')

    args = parser.parse_args()

    # Remove any characters that are not hex digits or spaces
    hex_string = args.frame.strip()
    if not re.fullmatch(r'([0-9A-Fa-f]{2}\s?)+', hex_string):
        print("Error: The frame contains invalid characters. Please provide a valid hexadecimal string.")
        exit(1)

    # Convert hex string to bytes
    frame_bytes = bytes.fromhex(hex_string)

    decoder = AX25Decoder()
    result = decoder.decode(frame_bytes)

    if result:
        print("Decoded Frame:")
        print("Destination Callsign: {}-{}".format(result['dest_callsign'], result['dest_ssid']))
        print("Source Callsign: {}-{}".format(result['src_callsign'], result['src_ssid']))
        print("Control Field: 0x{:02X}".format(result['control']))
        print("PID Field: 0x{:02X}".format(result['pid']))
        print("Information Field: {}".format(result['info']))
