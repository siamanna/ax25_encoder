# test.py

from ax25encoder import AX25Encoder
from ax25decoder import AX25Decoder

def test_ax25():
    # Set up test data
    src_callsign = 'TEST1'
    src_ssid = 0
    dest_callsign = 'DEST'
    dest_ssid = 0
    payload = input("Enter the payload to be sent: ")

    # Encode the frame
    encoder = AX25Encoder(src_callsign, src_ssid, dest_callsign, dest_ssid)
    encoded_frame = encoder.encode(payload)
    print('\nEncoded Frame (in hex):')
    print(' '.join(['{:02X}'.format(b) for b in encoded_frame]))
    print('')

    # Decode the frame
    decoder = AX25Decoder()
    decoded = decoder.decode(bytes(encoded_frame))
    if decoded:
        print('Decoded Frame:')
        print('Destination Callsign: {}-{}'.format(decoded['dest_callsign'], decoded['dest_ssid']))
        print('Source Callsign: {}-{}'.format(decoded['src_callsign'], decoded['src_ssid']))
        print('Control Field: 0x{:02X}'.format(decoded['control']))
        print('PID Field: 0x{:02X}'.format(decoded['pid']))
        print('Information Field: {}'.format(decoded['info']))

        # Check if the decoded payload matches the original payload
        if decoded['info'] == payload:
            print('\nTest Passed: The decoded payload matches the original payload.')
        else:
            print('\nTest Failed: The decoded payload does not match the original payload.')
            print('Original Payload: {}'.format(payload))
            print('Decoded Payload:  {}'.format(decoded['info']))
    else:
        print('Failed to decode frame')

if __name__ == "__main__":
    test_ax25()
