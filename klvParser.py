from misb0102 import SecurityMetadataLocalSet
from misb0903 import VMTIMetadataLocalSet
from misb0601_decoder import decode_misb0601_item, misb0601_key_names


class KLVParser:
    def __init__(self, rawBinary, key):
        self.rawBinary = rawBinary
        self.key = key
        self.keylength = len(key)
        self.result = {}

    def decode(self):
        parsed = self.parseGroups(self.constructGroups())
        for packetNum, items in parsed.items():
            self.result[packetNum] = {}
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
                
                # Handle general MISB0601 items
                else:
                    decoded_value = decode_misb0601_item(key, value)
                    descriptive_key = misb0601_key_names.get(key, f"Unknown Key {key}")
                    self.result[packetNum][descriptive_key] = decoded_value

    def constructGroups(self):
        groups = []
        bin_data = self.rawBinary
        key = bytes(self.key)
        key_length = len(self.key)
        i = 0

        while i < len(bin_data) - key_length + 1:
            if bin_data[i] == key[0] and bin_data[i:i + key_length] == key:
                groups.append(i)
                i += key_length
                section_length, length_of_length_field = self.readBERLength(bin_data[i:])
                i += length_of_length_field
                i += section_length
                continue
            i += 1
        return groups

    def parseGroups(self, groups):
        parsed = {}
        packetNum = 1
        for groupStartIndex in groups[:-1]:
            section_length, length_of_length_field = self.readBERLength(self.rawBinary[groupStartIndex + self.keylength:])
            endIndex = groupStartIndex + self.keylength + length_of_length_field + section_length
            valueStartIndex = groupStartIndex + self.keylength + length_of_length_field
            parsed[packetNum] = []

            while valueStartIndex < endIndex:
                miniSection_length, miniSection_length_of_length_field = self.readBERLength(self.rawBinary[valueStartIndex + 1:])
                parsed[packetNum].append({
                    'key': self.rawBinary[valueStartIndex],
                    'length': miniSection_length,
                    'value': self.rawBinary[valueStartIndex + 1 + miniSection_length_of_length_field : valueStartIndex + 1 + miniSection_length_of_length_field + miniSection_length]
                })
                valueStartIndex = valueStartIndex + 1 + miniSection_length_of_length_field + miniSection_length

            packetNum += 1
        return parsed

    def readBERLength(self, data):
        if len(data) == 0:
            return 0, 0
        first_byte = data[0]
        if first_byte & 0x80 == 0:
            return first_byte, 1
        else:
            num_length_bytes = first_byte & 0x7F
            length = 0
            for i in range(num_length_bytes):
                length = (length << 8) | data[i + 1]
            return length, 1 + num_length_bytes



# ------------- TESTING ------------- #

import csv

if __name__ == "__main__":
    with open('./goodwin.bin', 'rb') as f:
        rawBinary = f.read()

    # MISB0601 key
    uasLdsKey = [6, 14, 43, 52, 2, 11, 1, 1, 14, 1, 3, 1, 1, 0, 0, 0]

    data = KLVParser(rawBinary, uasLdsKey)
    data.decode()

    # Extract the parsed result
    parsed = data.result

    # Define the CSV file to write to
    csv_filename = 'klv_data_output2.csv'

    # Collect all unique keys across all packets
    all_keys = set()
    for packet_data in parsed.values():
        all_keys.update(packet_data.keys())
    
    all_keys = sorted(all_keys)  # Sorting the keys for consistent order

    # Open the CSV file and write the result
    with open(csv_filename, mode='w', newline='') as csvfile:
        # Create a CSV writer object
        writer = csv.writer(csvfile)

        # Write headers (Packet number and all unique keys)
        writer.writerow(["Packet"] + all_keys)

        # Write data for each packet
        for packet_num, packet_data in parsed.items():
            # Collect values for each key in the current packet, fill with None if the key is missing
            row = [packet_num] + [packet_data.get(key, None) for key in all_keys]
            writer.writerow(row)

    print(f"Data written to {csv_filename}")


    # parsed = data.parseGroups(data.constructGroups())

    # print('\nparsed:\n', parsed[1])
    # print('length of parsed:\n', len(parsed))

    print('\nparsed and decoded:\n', data.result[1])
    print('length of parsed and decoded:\n', len(data.result))
