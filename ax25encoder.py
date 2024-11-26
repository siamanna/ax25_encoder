# ax25encoder.py

import sys

class AX25Encoder:
    def __init__(self, src_callsign, src_ssid, dest_callsign, dest_ssid):
        self.src_callsign = src_callsign.upper()
        self.src_ssid = src_ssid
        self.dest_callsign = dest_callsign.upper()
        self.dest_ssid = dest_ssid

        self.control = 0x03  # UI-frame
        self.pid = 0xF0      # No layer 3 protocol implemented

    def encode_callsign(self, callsign, ssid):
        # Pad callsign to 6 characters
        callsign = callsign.ljust(6)
        encoded = []
        for char in callsign:
            encoded.append(ord(char.upper()) << 1)
        # Encode SSID
        ssid_byte = (0x60 | ((ssid & 0x0F) << 1))  # Set LSB to 0
        encoded.append(ssid_byte)
        return encoded

    def prepare_frame(self, payload):
        frame = []

        frame += self.encode_callsign(self.dest_callsign, self.dest_ssid)

        frame += self.encode_callsign(self.src_callsign, self.src_ssid)

        frame[13] |= 0x01

        frame.append(self.control)

        frame.append(self.pid)

        frame += [ord(c) for c in payload]

        crc = self.compute_crc(frame)
        # Append CRC to frame (LSB first)
        frame.append(crc & 0xFF)
        frame.append((crc >> 8) & 0xFF)

        return frame

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

    def bit_stuff(self, data_bits):
        stuffed_bits = []
        consecutive_ones = 0
        for bit in data_bits:
            stuffed_bits.append(bit)
            if bit == 1:
                consecutive_ones += 1
                if consecutive_ones == 5:
                    stuffed_bits.append(0)
                    consecutive_ones = 0
            else:
                consecutive_ones = 0
        return stuffed_bits

    def nrzi_encode(self, bits):
        encoded_bits = []
        last_nrzi_bit = 1  # NRZI starts with mark
        for bit in bits:
            if bit == 0:
                # NRZI encodes a '0' as a transition
                last_nrzi_bit ^= 1
            # else, NRZI encodes a '1' as no change
            encoded_bits.append(last_nrzi_bit)
        return encoded_bits

    def scramble(self, bits):
        sr = [0]*17  # Shift register initialized with zeros
        scrambled_bits = []
        for bit in bits:
            # Scrambler polynomial: x^17 + x^12 + 1
            feedback = sr[11] ^ sr[16]
            scrambled_bit = bit ^ feedback
            scrambled_bits.append(scrambled_bit)
            # Shift register
            sr = [scrambled_bit] + sr[:-1]
        return scrambled_bits

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

    def encode(self, payload):
        frame = self.prepare_frame(payload)
        data_bits = self.bits_from_bytes(frame)

        # Scramble
        scrambled_bits = self.scramble(data_bits)

        # NRZI encode
        nrzi_bits = self.nrzi_encode(scrambled_bits)

        # Bit stuff
        stuffed_bits = self.bit_stuff(nrzi_bits)

        # Add flags (0x7E) to the frame
        flag = [0x7E]
        flag_bits = self.bits_from_bytes(flag)
        encoded_bits = flag_bits + stuffed_bits + flag_bits

        # Convert bits back to bytes
        encoded_frame = self.bytes_from_bits(encoded_bits)

        return encoded_frame

if __name__ == "__main__":
    # Example usage:
    import argparse

    parser = argparse.ArgumentParser(description='AX.25 Encoder')
    parser.add_argument('--src', type=str, required=True, help='Source callsign')
    parser.add_argument('--src-ssid', type=int, default=0, help='Source SSID (0-15)')
    parser.add_argument('--dest', type=str, required=True, help='Destination callsign')
    parser.add_argument('--dest-ssid', type=int, default=0, help='Destination SSID (0-15)')
    parser.add_argument('--payload', type=str, required=True, help='Payload to send')

    args = parser.parse_args()

    encoder = AX25Encoder(args.src, args.src_ssid, args.dest, args.dest_ssid)
    encoded_frame = encoder.encode(args.payload)

    print('Encoded Frame (in hex):')
    print(' '.join(['{:02X}'.format(b) for b in encoded_frame]))
