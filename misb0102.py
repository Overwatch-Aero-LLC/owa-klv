# misb0102.py

class SecurityMetadataLocalSet:
    def __init__(self, raw_binary, security_key):
        self.security_key = security_key
        self.sec_parsed_keys = self.parse_local_set(raw_binary)

    def parse_local_set(self, raw_binary):
        """Parses the Security Local Set (ST0102) using the provided key."""
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

    def parse_security_klv(self, klv_array):
        sec_klv_obj_list = []
        # Assuming klv_array is a list of dicts with 'key' and 'value'
        for item in klv_array:
            key = item.get('key')
            value = item.get('value')
            if key is not None and value is not None:
                sec_klv_obj_list.append(self.decode_security_item(key, value))
        return sec_klv_obj_list

    def decode_security_item(self, key, value):
        decode_functions = {
            1: self.security_classification,
            2: self.class_country_release_inst,
            3: self.classifying_country,
            4: self.security_sci_information,
            5: self.caveats,
            6: self.releasing_instructions,
            7: self.classified_by,
            8: self.derived_from,
            9: self.classification_reason,
            10: self.declassification_date,
            11: self.classification_markings,
            12: self.obj_country_code_method,
            13: self.obj_country_codes,
            14: self.classification_comments,
            22: self.version,
            23: self.class_country_date,
            24: self.obj_country_code_date
        }
        return decode_functions.get(key, lambda x: f"Unknown Key {key}")(value)

    def security_classification(self, value):
        classifications = {
            1: 'UNCLASSIFIED',
            2: 'RESTRICTED',
            3: 'CONFIDENTIAL',
            4: 'SECRET',
            5: 'TOP SECRET'
        }
        return classifications.get(value[0], 'UNKNOWN')

    def class_country_release_inst(self, value):
        methods = {
            1: 'ISO-3166 Two Letter',
            2: 'ISO-3166 Three Letter',
            3: 'FIPS 10-4 Two Letter',
            4: 'FIPS 10-4 Four Letter',
            5: 'ISO-3166 Numeric',
            6: '1059 Two Letter',
            7: '1059 Three Letter',
            10: 'FIPS 10-4 Mixed',
            11: 'ISO-3166 Mixed',
            12: 'STANAG 1059 Mixed',
            13: 'GENC Two Letter',
            14: 'GENC Three Letter',
            15: 'GENC Numeric',
            16: 'GENC Mixed'
        }
        return methods.get(value[0], 'UNKNOWN')

    def classifying_country(self, value):
        return value.decode('utf-8').rstrip('\x00')

    def security_sci_information(self, value):
        return value.decode('utf-8').rstrip('\x00')

    def caveats(self, value):
        return value.decode('utf-8').rstrip('\x00')

    def releasing_instructions(self, value):
        return value.decode('utf-8').rstrip('\x00')

    def classified_by(self, value):
        return value.decode('utf-8').rstrip('\x00')

    def derived_from(self, value):
        return value.decode('utf-8').rstrip('\x00')

    def classification_reason(self, value):
        return value.decode('utf-8').rstrip('\x00')

    def declassification_date(self, value):
        return value.decode('utf-8').rstrip('\x00')

    def classification_markings(self, value):
        return value.decode('utf-8').rstrip('\x00')

    def obj_country_code_method(self, value):
        methods = {
            1: 'ISO-3166 Two Letter',
            2: 'ISO-3166 Three Letter',
            3: 'ISO-3166 Numeric',
            4: 'FIPS 10-4 Two Letter',
            5: 'FIPS 10-4 Four Letter',
            6: '1059 Two Letter',
            7: '1059 Three Letter',
            13: 'GENC Two Letter',
            14: 'GENC Three Letter',
            15: 'GENC Numeric',
            16: 'GENC AdminSub'
        }
        return methods.get(value[0], 'UNKNOWN')

    def obj_country_codes(self, value):
        return value.decode('utf-8').rstrip('\x00')

    def classification_comments(self, value):
        return value.decode('utf-8').rstrip('\x00')

    def version(self, value):
        return int.from_bytes(value, byteorder='big')

    def class_country_date(self, value):
        return value.decode('utf-8').rstrip('\x00')

    def obj_country_code_date(self, value):
        return value.decode('utf-8').rstrip('\x00')
