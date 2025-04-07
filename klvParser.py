from misb0102 import SecurityMetadataLocalSet
from misb0903 import VMTIMetadataLocalSet
from misb0601_decoder import decode_misb0601_item, misb0601_key_names


class KLVParser:
    """
    A parser for KLV (Key Length Value) encoded binary data. This class:
    - Identifies and extracts MISB0601 packets using the provided UAS LDS Key.
    - Decodes the packets into their constituent fields.
    - Validates each packet's checksum.
    - Handles special cases for Security Local Set (MISB0102) and VMTI Local Set (MISB0903).
    """

    def __init__(self, rawBinary, key):
        """
        Initialize the KLVParser.

        :param rawBinary: The raw binary data containing one or more KLV packets.
        :param key: The UAS LDS Key (a sequence of bytes) used to identify MISB0601 packets.
        """
        self.rawBinary = rawBinary
        self.key = key
        self.keylength = len(key)
        self.result = {}

    def decode(self):
        """
        Decode all MISB0601 packets found in the raw binary data.

        This method:
        - Constructs packet groups based on the provided UAS LDS Key.
        - Parses each identified group into individual items.
        - Validates checksums for each packet.
        - Decodes MISB0601 fields.
        - Handles Security and VMTI local sets specially.
        - Stores decoded results in self.result.
        """
        parsed = self.parseGroups(self.constructGroups())
        for packetNum, items in parsed.items():
            self.result[packetNum] = {}

            # Decode each item in the packet
            for item in items:
                key = item['key']
                value = item['value']

                # Handle Security Local Set
                if key == 48:
                    sec_meta = SecurityMetadataLocalSet(value, self.key)
                    self.result[packetNum]['Security Local Set'] = sec_meta.parse_security_klv(sec_meta.sec_parsed_keys)

                # Handle VMTI Local Set
                elif key == 74:
                    vmti_meta = VMTIMetadataLocalSet(value, self.key)
                    self.result[packetNum]['VMTI Local Set'] = vmti_meta.parse_vmti_klv(vmti_meta.vmti_parsed_keys)

                # Handle general MISB0601 items (excluding the checksum key)
                elif key != 1:
                    decoded_value = decode_misb0601_item(key, value)
                    descriptive_key = misb0601_key_names.get(key, f"Unknown Key {key}")
                    self.result[packetNum][descriptive_key] = decoded_value

    def constructGroups(self):
        """
        Identify the start indices of all packets in the raw binary data that match the given key.
        
        :return: A list of indices where each packet (identified by the UAS LDS Key) starts.
        """
        groups = []
        bin_data = self.rawBinary
        key = bytes(self.key)
        key_length = self.keylength
        i = 0

        # Scan through the binary data to find occurrences of the UAS LDS Key
        while i < len(bin_data) - key_length + 1:
            # Check if the current position matches the key
            if bin_data[i:i + key_length] == key:
                groups.append(i)
                i += key_length
                section_length, length_of_length_field = self.readBERLength(bin_data[i:])
                i += length_of_length_field
                i += section_length
                continue
            i += 1

        return groups

    def parseGroups(self, groups):
        """
        Parse each identified packet group into its constituent items.

        :param groups: A list of indices where each packet starts.
        :return: A dictionary keyed by packet number, with each value containing a list of parsed items.
        """
        parsed = {}
        packetNum = 1

        # Iterate through all but the last group because we determine packet boundaries from offsets
        for groupStartIndex in groups[:-1]:
            section_length, length_of_length_field = self.readBERLength(
                self.rawBinary[groupStartIndex + self.keylength:]
            )
            endIndex = groupStartIndex + self.keylength + length_of_length_field + section_length
            valueStartIndex = groupStartIndex + self.keylength + length_of_length_field

            parsed[packetNum] = []

            # Extract the raw packet data for checksum calculation
            raw_packet_data = self.rawBinary[groupStartIndex:endIndex]

            # Parse each KLV item within the packet
            while valueStartIndex < endIndex:
                miniSection_length, miniSection_length_of_length_field = self.readBERLength(
                    self.rawBinary[valueStartIndex + 1:]
                )
                parsed[packetNum].append({
                    'key': self.rawBinary[valueStartIndex],
                    'length': miniSection_length,
                    'value': self.rawBinary[
                        valueStartIndex + 1 + miniSection_length_of_length_field:
                        valueStartIndex + 1 + miniSection_length_of_length_field + miniSection_length
                    ],
                    'raw_item_bytes': self.rawBinary[
                        valueStartIndex:
                        valueStartIndex + 1 + miniSection_length_of_length_field + miniSection_length
                    ]
                })
                valueStartIndex += 1 + miniSection_length_of_length_field + miniSection_length

            # Validate checksum if present
            provided_checksum = None
            for item in parsed[packetNum]:
                if item['key'] == 1:  # Checksum key
                    provided_checksum = int.from_bytes(item['value'], byteorder='big')

            if provided_checksum is not None:
                calculated_checksum = self.calculate_checksum(raw_packet_data[:-2])  # Exclude the checksum field
                if calculated_checksum != provided_checksum:
                    print(f"Packet {packetNum} checksum mismatch: {calculated_checksum} != {provided_checksum}")
                    del parsed[packetNum]  # Remove the packet if checksum fails
                    continue

            packetNum += 1

        return parsed

    def readBERLength(self, data):
        """
        Read a BER (Basic Encoding Rules) encoded length field.

        In MISB KLV:
        - If the top bit is clear, the value is the length.
        - If the top bit is set, the next 'n' bytes (where 'n' is the value of the lower 7 bits)
          represent the length.

        :param data: The raw bytes starting at the BER length field.
        :return: A tuple (length, length_of_length_field)
        """
        if len(data) == 0:
            return 0, 0

        first_byte = data[0]
        # If the high bit is not set, the length fits in one byte
        if first_byte & 0x80 == 0:
            return first_byte, 1
        else:
            # If the high bit is set, next 'num_length_bytes' bytes form the length
            num_length_bytes = first_byte & 0x7F
            length = 0
            for i in range(num_length_bytes):
                length = (length << 8) | data[i + 1]
            return length, 1 + num_length_bytes

    def calculate_checksum(self, packet_data):
        """
        Calculate a 2-byte checksum for the given packet data. The checksum is defined in MISB0601
        as a 16-bit sum of the data, where bytes alternate position in the sum.

        :param packet_data: The raw packet data excluding the checksum field itself.
        :return: The calculated 16-bit checksum as an integer.
        """
        checksum = 0
        # Perform sum with alternating shifts
        for i, byte in enumerate(packet_data):
            checksum += byte << (8 * ((i + 1) % 2))
        return checksum & 0xFFFF


# ------------- TESTING ------------- #

import csv

if __name__ == "__main__":
    with open('./goodwin_trimmed_5kb.bin', 'rb') as f:
        rawBinary = f.read()

    # MISB0601 key
    uasLdsKey = [6, 14, 43, 52, 2, 11, 1, 1, 14, 1, 3, 1, 1, 0, 0, 0]

    data = KLVParser(rawBinary, uasLdsKey)
    data.decode()

    # Extract the parsed result
    parsed = data.result

    # # Define the CSV file to write to
    # csv_filename = 'klv_data_output2.csv'

    # # Collect all unique keys across all packets
    # all_keys = set()
    # for packet_data in parsed.values():
    #     all_keys.update(packet_data.keys())
    
    # all_keys = sorted(all_keys)  # Sorting the keys for consistent order

    # # Open the CSV file and write the result
    # with open(csv_filename, mode='w', newline='') as csvfile:
    #     # Create a CSV writer object
    #     writer = csv.writer(csvfile)

    #     # Write headers (Packet number and all unique keys)
    #     writer.writerow(["Packet"] + all_keys)

    #     # Write data for each packet
    #     for packet_num, packet_data in parsed.items():
    #         # Collect values for each key in the current packet, fill with None if the key is missing
    #         row = [packet_num] + [packet_data.get(key, None) for key in all_keys]
    #         writer.writerow(row)

    # print(f"Data written to {csv_filename}")

    # parsed = data.parseGroups(data.constructGroups())

    # print('\nparsed:\n', parsed[1])
    # print('length of parsed:\n', len(parsed))

    print('\nparsed and decoded:\n', data.result[7])
    print('length of parsed and decoded:\n', len(data.result))
    # print(data.result)
