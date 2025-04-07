# misb0903.py

class VMTIMetadataLocalSet:
    def __init__(self, raw_binary, vmti_key):
        self.vmti_key = vmti_key
        self.vmti_parsed_keys = self.parse_local_set(raw_binary)

    def parse_local_set(self, raw_binary):
        """Parses the VMTI Local Set (ST0903) using the provided key."""
        parsed_keys = []
        i = 0

        while i < len(raw_binary):
            # Read the key (1 byte or multiple bytes depending on encoding)
            key = raw_binary[i]
            i += 1

            # Read the length (BER-encoded length)
            length, length_of_length_field = self.read_ber_length(raw_binary[i:])
            i += length_of_length_field

            # Read the value
            value = raw_binary[i:i + length]
            i += length

            # Append the parsed key-value pair
            parsed_keys.append({'key': key, 'value': value})

        return parsed_keys

    def read_ber_length(self, data):
        """Decodes the BER length field."""
        first_byte = data[0]
        if first_byte & 0x80 == 0:  # Short form
            return first_byte, 1
        else:  # Long form
            num_length_bytes = first_byte & 0x7F
            length = 0
            for i in range(num_length_bytes):
                length = (length << 8) | data[i + 1]
            return length, 1 + num_length_bytes

    def parse_vmti_klv(self, klv_array):
        vmti_klv_obj_list = []
        # Assuming klv_array is a list of dicts with 'key' and 'value'
        for item in klv_array:
            key = item.get('key')
            value = item.get('value')
            if key is not None and value is not None:
                vmti_klv_obj_list.append(self.decode_vmti_item(key, value))
        return vmti_klv_obj_list

    def decode_vmti_item(self, key, value):
        decode_functions = {
            1: self.checksum,
            2: self.precision_time_stamp,
            3: self.vmti_system_name,
            4: self.vmti_ls_version_num,
            5: self.total_num_targets_detected,
            6: self.num_targets_reported,
            7: self.number_of_rois,
            8: self.frame_width,
            9: self.frame_height,
            10: self.vmti_source_sensor,
            11: self.vmti_horizontal_fov,
            12: self.vmti_vertical_fov,
            13: self.miis_id,
            101: self.v_target_series,
            102: self.algorithm_series,
            103: self.ontology_series
        }
        return decode_functions.get(key, lambda x: f"Unknown Key {key}")(value)

    def checksum(self, value):
        return int.from_bytes(value, byteorder='big')

    def precision_time_stamp(self, value):
        return int.from_bytes(value, byteorder='big') / 1000.0

    def vmti_system_name(self, value):
        return value.decode('utf-8').rstrip('\x00')

    def vmti_ls_version_num(self, value):
        return int.from_bytes(value, byteorder='big')

    def total_num_targets_detected(self, value):
        return int.from_bytes(value, byteorder='big')

    def num_targets_reported(self, value):
        return int.from_bytes(value, byteorder='big')
    
    def number_of_rois(self, value):
        """
        Decoder for Key 7 in ST 0903: Number of Regions of Interest (ROI) Reported.
        Typically a 1-byte unsigned integer.
        """
        return int.from_bytes(value, byteorder='big')

    def frame_width(self, value):
        return int.from_bytes(value, byteorder='big')

    def frame_height(self, value):
        return int.from_bytes(value, byteorder='big')

    def vmti_source_sensor(self, value):
        return value.decode('utf-8').rstrip('\x00')

    def vmti_horizontal_fov(self, value):
        return 'IMAPB Required'

    def vmti_vertical_fov(self, value):
        return 'IMAPB Required'

    def miis_id(self, value):
        return value

    def v_target_series(self, value):
        return value

    def algorithm_series(self, value):
        return value

    def ontology_series(self, value):
        return value
