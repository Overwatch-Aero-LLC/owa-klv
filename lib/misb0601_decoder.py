from lib.misb0102 import SecurityMetadataLocalSet
from lib.misb0903 import VMTIMetadataLocalSet

# Mapping MISB0601 keys to descriptive names
misb0601_key_names = {
    1: 'Checksum',
    2: 'Precision Time Stamp',
    3: 'Mission ID',
    4: 'Platform Tail Number',
    5: 'Platform Heading Angle',
    6: 'Platform Pitch Angle',
    7: 'Platform Roll Angle',
    8: 'Platform True Airspeed',
    9: 'Platform Indicated Airspeed',
    10: 'Platform Designation',
    11: 'Image Source Sensor',
    12: 'Image Coordinate System',
    13: 'Sensor Latitude',
    14: 'Sensor Longitude',
    15: 'Sensor True Altitude',
    16: 'Sensor Horizontal Field of View',
    17: 'Sensor Vertical Field of View',
    18: 'Sensor Relative Azimuth Angle',
    19: 'Sensor Relative Elevation Angle',
    20: 'Sensor Relative Roll Angle',
    21: 'Slant Range',
    22: 'Target Width',
    23: 'Frame Center Latitude',
    24: 'Frame Center Longitude',
    25: 'Frame Center Elevation',
    26: 'Offset Corner Latitude Point 1',
    27: 'Offset Corner Longitude Point 1',
    28: 'Offset Corner Latitude Point 2',
    29: 'Offset Corner Longitude Point 2',
    30: 'Offset Corner Latitude Point 3',
    31: 'Offset Corner Longitude Point 3',
    32: 'Offset Corner Latitude Point 4',
    33: 'Offset Corner Longitude Point 4',
    34: 'Icing Detected',
    35: 'Wind Direction',
    36: 'Wind Speed',
    37: 'Static Pressure',
    38: 'Density Altitude',
    39: 'Outside Air Temperature',
    40: 'Target Location Latitude',
    41: 'Target Location Longitude',
    42: 'Target Location Elevation',
    43: 'Target Track Gate Width',
    44: 'Target Track Gate Height',
    45: 'Target Error Estimate CE90',
    46: 'Target Error Estimate LE90',
    47: 'Generic Flag Data',
    48: 'Security Local Set',
    49: 'Differential Pressure',
    50: 'Platform Angle of Attack',
    51: 'Platform Vertical Speed',
    52: 'Platform Sideslip Angle',
    53: 'Airfield Barometric Pressure',
    54: 'Airfield Elevation',
    55: 'Relative Humidity',
    56: 'Platform Ground Speed',
    57: 'Ground Range',
    58: 'Platform Fuel Remaining',
    59: 'Platform Call Sign',
    60: 'Weapon Load',
    61: 'Weapon Fired',
    62: 'Laser PRF Code',
    63: 'Sensor Field of View Name',
    64: 'Platform Magnetic Heading',
    65: 'UAS Datalink LS Version Number',
    66: 'Deprecated',
    67: 'Alternate Platform Latitude',
    68: 'Alternate Platform Longitude',
    69: 'Alternate Platform Altitude',
    70: 'Alternate Platform Name',
    71: 'Alternate Platform Heading',
    72: 'Event Start Time UTC',
    73: 'RVT Local Set Conversion',
    74: 'VMTI Local Set',
    75: 'Sensor Ellipsoid Height',
    76: 'Alternate Platform Ellipsoid Height',
    77: 'Operational Mode',
    78: 'Frame Center Height Above Ellipsoid',
    79: 'Sensor North Velocity',
    80: 'Sensor East Velocity',
    81: 'Image Horizon Pixel Pack',
    82: 'Offset Corner Latitude Point 1 (Full)',
    83: 'Offset Corner Longitude Point 1 (Full)',
    84: 'Offset Corner Latitude Point 2 (Full)',
    85: 'Offset Corner Longitude Point 2 (Full)',
    86: 'Offset Corner Latitude Point 3 (Full)',
    87: 'Offset Corner Longitude Point 3 (Full)',
    88: 'Offset Corner Latitude Point 4 (Full)',
    89: 'Offset Corner Longitude Point 4 (Full)',
    90: 'Platform Pitch Angle (Full)',
    91: 'Platform Roll Angle (Full)',
    92: 'Platform Angle of Attack (Full)',
    93: 'Platform Sideslip Angle (Full)',
    94: 'MIIS Core Identifier',
    95: 'SAR Motion Imagery Metadata',
    97: 'Reserved',
    98: 'Reserved',
    99: 'Reserved',
    100: 'Reserved',
    101: 'Reserved',
    102: 'Reserved',
    103: 'Density Altitude Extended',
    104: 'Sensor Ellipsoid Height Extended',
    105: 'Alternate Platform Ellipsoid Height Extended',
}

def decode_misb0601_item(key, value):
    # Mapping each key to the corresponding decode function
    decode_functions = {
        1: decode_checksum,
        2: decode_precision_time_stamp,
        3: decode_mission_id,
        4: decode_platform_tail_number,
        5: decode_platform_heading_angle,
        6: decode_platform_pitch_angle,
        7: decode_platform_roll_angle,
        8: decode_platform_true_airspeed,
        9: decode_platform_indicated_airspeed,
        10: decode_platform_designation,
        11: decode_image_source_sensor,
        12: decode_image_coordinate_system,
        13: decode_sensor_latitude,
        14: decode_sensor_longitude,
        15: decode_sensor_true_altitude,
        16: decode_sensor_horizontal_field_of_view,
        17: decode_sensor_vertical_field_of_view,
        18: decode_sensor_relative_azimuth_angle,
        19: decode_sensor_relative_elevation_angle,
        20: decode_sensor_relative_roll_angle,
        21: decode_slant_range,
        22: decode_target_width,
        23: decode_frame_center_latitude,
        24: decode_frame_center_longitude,
        25: decode_frame_center_elevation,
        26: decode_offset_corner_latitude_point_1,
        27: decode_offset_corner_longitude_point_1,
        28: decode_offset_corner_latitude_point_2,
        29: decode_offset_corner_longitude_point_2,
        30: decode_offset_corner_latitude_point_3,
        31: decode_offset_corner_longitude_point_3,
        32: decode_offset_corner_latitude_point_4,
        33: decode_offset_corner_longitude_point_4,
        34: decode_icing_detected,
        35: decode_wind_direction,
        36: decode_wind_speed,
        37: decode_static_pressure,
        38: decode_density_altitude,
        39: decode_outside_air_temperature,
        40: decode_target_location_latitude,
        41: decode_target_location_longitude,
        42: decode_target_location_elevation,
        43: decode_target_track_gate_width,
        44: decode_target_track_gate_height,
        45: decode_target_error_estimate_ce90,
        46: decode_target_error_estimate_le90,
        47: decode_generic_flag_data,
        48: decode_security_local_set,
        49: decode_differential_pressure,
        50: decode_platform_angle_of_attack,
        51: decode_platform_vertical_speed,
        52: decode_platform_sideslip_angle,
        53: decode_airfield_barometric_pressure,
        54: decode_airfield_elevation,
        55: decode_relative_humidity,
        56: decode_platform_ground_speed,
        57: decode_ground_range,
        58: decode_platform_fuel_remaining,
        59: decode_platform_call_sign,
        60: decode_weapon_load,
        61: decode_weapon_fired,
        62: decode_laser_prf_code,
        63: decode_sensor_field_of_view_name,
        64: decode_platform_magnetic_heading,
        65: decode_uas_datalink_ls_version_number,
        66: decode_deprecated,
        67: decode_alternate_platform_latitude,
        68: decode_alternate_platform_longitude,
        69: decode_alternate_platform_altitude,
        70: decode_alternate_platform_name,
        71: decode_alternate_platform_heading,
        72: decode_event_start_time_utc,
        73: decode_rvt_local_set,
        74: decode_vmti_local_set,
        75: decode_sensor_ellipsoid_height,
        76: decode_alternate_platform_ellipsoid_height,
        77: decode_operational_mode,
        78: decode_frame_center_height_above_ellipsoid,
        79: decode_sensor_north_velocity,
        80: decode_sensor_east_velocity,
        81: decode_image_horizon_pixel_pack,
        82: decode_offset_corner_latitude_point_1_full,
        83: decode_offset_corner_longitude_point_1_full,
        84: decode_offset_corner_latitude_point_2_full,
        85: decode_offset_corner_longitude_point_2_full,
        86: decode_offset_corner_latitude_point_3_full,
        87: decode_offset_corner_longitude_point_3_full,
        88: decode_offset_corner_latitude_point_4_full,
        89: decode_offset_corner_longitude_point_4_full,
        90: decode_platform_pitch_angle_full,
        91: decode_platform_roll_angle_full,
        92: decode_platform_angle_of_attack_full,
        93: decode_platform_sideslip_angle_full,
        94: decode_miis_core_identifier,
        95: decode_sar_motion_imagery_metadata,
        96: decode_target_width_extended,
        97: decode_reserved,
        98: decode_reserved,
        99: decode_reserved,
        100: decode_reserved,
        101: decode_reserved,
        102: decode_reserved,
        103: decode_density_altitude_extended,
        104: decode_sensor_ellipsoid_height_extended,
        105: decode_alternate_platform_ellipsoid_height_extended,
    }
    # Call the corresponding function if exists
    return decode_functions.get(key, lambda v: v)(value)

# Below are the decoding functions for each MISB0601 key.

def decode_checksum(value):
    return int.from_bytes(value, byteorder='big')

def decode_precision_time_stamp(value):
    return int.from_bytes(value, byteorder='big') / 1000.0

def decode_mission_id(value):
    return value.decode('utf-8')

def decode_platform_tail_number(value):
    return value.decode('utf-8')

def decode_platform_heading_angle(value):
    return uint_to_float(value, (0, (2**16) - 1), (0, 360))

def decode_platform_pitch_angle(value):
    value = int.from_bytes(value, byteorder='big', signed=True)
    return ((value / (2**15)) * 20) if value != -2**15 else float('NaN')

def decode_platform_roll_angle(value):
    value = int.from_bytes(value, byteorder='big', signed=True)
    return ((value / (2**15)) * 50) if value != -2**15 else float('NaN')

def decode_platform_true_airspeed(value):
    return uint_to_float(value, (0, 255), (0, 255))

def decode_platform_indicated_airspeed(value):
    return uint_to_float(value, (0, 255), (0, 255))

def decode_platform_designation(value):
    return value.decode('utf-8')

def decode_image_source_sensor(value):
    return value.decode('utf-8')

def decode_image_coordinate_system(value):
    return value.decode('utf-8')

def decode_sensor_latitude(byte_seq):
    value = int.from_bytes(byte_seq, byteorder='big', signed=False)
    return (value / (2**31)) * 90

def decode_sensor_longitude(byte_seq):
    LS_int = int.from_bytes(byte_seq, byteorder='big', signed=True)
    return (360 / 4294967294) * LS_int

def decode_sensor_true_altitude(byte_seq):
    value = int.from_bytes(byte_seq, byteorder='big', signed=False)
    return (19900 / 65535) * value - 900


def decode_sensor_horizontal_field_of_view(value):
    return uint_to_float(value, (0, (2**16) - 1), (0, 180))

def decode_sensor_vertical_field_of_view(value):
    return uint_to_float(value, (0, (2**16) - 1), (0, 180))

def decode_sensor_relative_azimuth_angle(byte_seq):
    LS_uint = int.from_bytes(byte_seq, byteorder='big', signed=False)
    return (360 / (2**32 - 1)) * LS_uint


def decode_sensor_relative_elevation_angle(byte_seq):
    value = int.from_bytes(byte_seq, byteorder='big', signed=True)
    return (value / (2**31)) * 180 if value != -2**31 else float('NaN')

def decode_sensor_relative_roll_angle(byte_seq):
    value = int.from_bytes(byte_seq, byteorder='big', signed=True)
    return (value / (2**31)) * 360 if value != -2**31 else float('NaN')


def decode_slant_range(value):
    return uint_to_float(value, (0, (2**32) - 1), (0, 5000000))

def decode_target_width(value):
    return uint_to_float(value, (0, (2**16) - 1), (0, 10000))

def decode_frame_center_latitude(value):
    value = int.from_bytes(value, byteorder='big', signed=False)
    return (value / (2**31)) * 90


def decode_frame_center_longitude(value):
    LS_int = int.from_bytes(value, byteorder='big', signed=True)
    return (360 / 4294967294) * LS_int

def decode_frame_center_elevation(value):
    value = int.from_bytes(value, byteorder='big', signed=False)
    return (19900 / 65535) * value - 900

def decode_offset_corner_latitude_point_1(value):
    value = int.from_bytes(value, byteorder='big', signed=True)
    return (value / (2**15)) * 0.075


def decode_offset_corner_longitude_point_1(value):
    value = int.from_bytes(value, byteorder='big', signed=True)
    return (value / (2**15)) * 0.075


def decode_offset_corner_latitude_point_2(value):
    value = int.from_bytes(value, byteorder='big', signed=True)
    return (value / (2**15)) * 0.075

def decode_offset_corner_longitude_point_2(value):
    value = int.from_bytes(value, byteorder='big', signed=True)
    return (value / (2**15)) * 0.075

def decode_offset_corner_latitude_point_3(value):
    value = int.from_bytes(value, byteorder='big', signed=True)
    return (value / (2**15)) * 0.075

def decode_offset_corner_longitude_point_3(value):
    value = int.from_bytes(value, byteorder='big', signed=True)
    return (value / (2**15)) * 0.075

def decode_offset_corner_latitude_point_4(value):
    value = int.from_bytes(value, byteorder='big', signed=True)
    return (value / (2**15)) * 0.075

def decode_offset_corner_longitude_point_4(value):
    value = int.from_bytes(value, byteorder='big', signed=True)
    return (value / (2**15)) * 0.075

def decode_platform_pitch_angle_full(byte_seq):
    LS_int = int.from_bytes(byte_seq, byteorder='big', signed=True)
    return (180 / 4294967294) * LS_int

def decode_platform_roll_angle_full(byte_seq):
    LS_int = int.from_bytes(byte_seq, byteorder='big', signed=True)
    return (180 / 4294967294) * LS_int

def decode_icing_detected(value):
    return uint_to_float(value, (0, 2), (0, 2))

def decode_wind_direction(value):
    return uint_to_float(value, (0, (2**16) - 1), (0, 360))

def decode_wind_speed(value):
    return uint_to_float(value, (0, 255), (0, 100))

def decode_static_pressure(value):
    return uint_to_float(value, (0, (2**16) - 1), (0, 5000))

def decode_density_altitude(value):
    return uint_to_float(value, (0, (2**16) - 1), (-900, 19000))

def decode_outside_air_temperature(value):
    return int_to_float(value, (-128, 127), (-128, 127))

def decode_target_location_latitude(byte_seq):
    value = int.from_bytes(byte_seq, byteorder='big', signed=False)
    return (value / (2**31)) * 90

def decode_target_location_longitude(byte_seq):
    LS_int = int.from_bytes(byte_seq, byteorder='big', signed=True)
    return (360 / 4294967294) * LS_int

def decode_target_location_elevation(byte_seq):
    value = int.from_bytes(byte_seq, byteorder='big', signed=False)
    return (19900 / 65535) * value - 900

def decode_target_track_gate_width(value):
    return uint_to_float(value, (0, 255), (0, 510))

def decode_target_track_gate_height(value):
    return uint_to_float(value, (0, 255), (0, 510))

def decode_target_error_estimate_ce90(value):
    return uint_to_float(value, (0, (2**16) - 1), (0, 4095))

def decode_target_error_estimate_le90(value):
    value = int.from_bytes(value, byteorder='big', signed=False)
    return (4095/65535) * value

def decode_generic_flag_data(value):
    """Decode the Generic Flag Data (1 byte) as a series of bit flags."""
    if len(value) != 1:
        raise ValueError("Generic Flag Data should be 1 byte long.")
    
    # Convert the byte to an integer for bit manipulation
    flag_byte = value[0]
    
    flags = {
        "Laser Range": bool(flag_byte & 0b10000000),
        "Auto-Track": bool(flag_byte & 0b01000000),
        "IR Polarity (1=black, 0=white)": bool(flag_byte & 0b00100000),
        "Icing Detected": bool(flag_byte & 0b00010000),
        "Slant Range Measured": bool(flag_byte & 0b00001000),
        "Image Invalid": bool(flag_byte & 0b00000100),
    }
    
    return flags

def decode_security_local_set(value):
    """Decode the Security Local Set (Key 48) using ST0102."""
    sec_meta = SecurityMetadataLocalSet(value, security_key=[6, 14, 43, 52, 2, 3, 1, 1, 14, 1, 3, 3, 2, 0, 0, 0])
    return sec_meta.parse_security_klv(sec_meta.sec_parsed_keys)

def decode_differential_pressure(value):
    return uint_to_float(value, (0, (2**16) - 1), (0, 5000))

def decode_platform_angle_of_attack(value):
    return int_to_float(value, (-((2**15) - 1), (2**15) - 1), (-20, 20))

def decode_platform_vertical_speed(byte_seq):
    value = int.from_bytes(byte_seq, byteorder='big', signed=True)
    return (value / (2**15)) * 180 if value != -2**15 else float('NaN')


def decode_platform_sideslip_angle(value):
    return int_to_float(value, (-((2**15) - 1), (2**15) - 1), (-20, 20))

def decode_airfield_barometric_pressure(value):
    return uint_to_float(value, (0, (2**16) - 1), (0, 5000))

def decode_airfield_elevation(value):
    return uint_to_float(value, (0, (2**16) - 1), (-900, 19000))

def decode_relative_humidity(value):
    return uint_to_float(value, (0, (2**8) - 1), (0, 100))

def decode_platform_ground_speed(value):
    return uint_to_float(value, (0, (2**8) - 1), (0, 255))

def decode_ground_range(value):
    return uint_to_float(value, (0, (2**32) - 1), (0, 5000000))

def decode_platform_fuel_remaining(value):
    return uint_to_float(value, (0, (2**16) - 1), (0, 10000))

def decode_platform_call_sign(value):
    return value.decode('utf-8')

def decode_weapon_load(value):
    return value

def decode_weapon_fired(value):
    return value

def decode_laser_prf_code(value):
    return uint_to_float(value, (0, (2**16)), (0, (2**16)))

def decode_sensor_field_of_view_name(value):
    field_of_view_map = {
        0: 'Ultranarrow',
        1: 'Narrow',
        2: 'Medium',
        3: 'Wide',
        4: 'Ultrawide',
        5: 'Narrow Medium',
        6: '2x Ultranarrow',
        7: '4x Ultranarrow',
        8: 'Continuous Zoom'
    }
    return field_of_view_map.get(value[0], 'Unknown')

def decode_platform_magnetic_heading(value):
    return uint_to_float(value, (0, (2**16) - 1), (0, 360))

def decode_uas_datalink_ls_version_number(value):
    return uint_to_float(value, (0, (2**8)), (0, (2**8)))

def decode_deprecated(value):
    return 'DEPRECATED'

def decode_alternate_platform_latitude(value):
    return int_to_float(value, (-((2**31) - 1), (2**31) - 1), (-90, 90))

def decode_alternate_platform_longitude(value):
    return int_to_float(value, (-((2**31) - 1), (2**31) - 1), (-180, 180))

def decode_alternate_platform_altitude(value):
    return uint_to_float(value, (0, (2**16) - 1), (-900, 19000))

def decode_alternate_platform_name(value):
    return value.decode('utf-8')

def decode_alternate_platform_heading(value):
    return uint_to_float(value, (0, (2**16) - 1), (0, 360))

def decode_event_start_time_utc(value):
    return int.from_bytes(value, byteorder='big') / 1000.0

def decode_vmti_local_set(value):
    """Decode the VMTI Local Set (Key 74) using ST0903."""
    vmti_meta = VMTIMetadataLocalSet(value, vmti_key=[6, 14, 43, 52, 2, 11, 1, 1, 14, 1, 3, 3, 6, 0, 0, 0])
    return vmti_meta.parse_vmti_klv(vmti_meta.vmti_parsed_keys)

def decode_sensor_ellipsoid_height(byte_seq):
    value = int.from_bytes(byte_seq, byteorder='big', signed=False)
    return (19900 / 65535) * value - 900


def decode_alternate_platform_ellipsoid_height(value):
    return uint_to_float(value, (0, (2**16) - 1), (-900, 19000))

def decode_operational_mode(value):
    mode_map = {
        0: 'Other',
        1: 'Operational',
        2: 'Training',
        3: 'Exercise',
        4: 'Maintenance',
        5: 'Test'
    }
    return mode_map.get(value[0], 'Unknown')

def decode_frame_center_height_above_ellipsoid(byte_seq):
    value = int.from_bytes(byte_seq, byteorder='big', signed=False)
    return ((value / 65535) * (19000 + 900)) - 900


def decode_sensor_north_velocity(byte_seq):
    value = int.from_bytes(byte_seq, byteorder='big', signed=True)
    return (value / (2**15)) * 327 if value != -2**15 else float('NaN')

def decode_sensor_east_velocity(byte_seq):
    value = int.from_bytes(byte_seq, byteorder='big', signed=True)
    return (value / (2**15)) * 327 if value != -2**15 else float('NaN')


def decode_offset_corner_latitude_point_1_full(value):
    return int_to_float(value, (-((2**31) - 1), (2**31) - 1), (-90, 90))

def decode_offset_corner_longitude_point_1_full(value):
    return int_to_float(value, (-((2**31) - 1), (2**31) - 1), (-180, 180))

def decode_offset_corner_latitude_point_2_full(value):
    return int_to_float(value, (-((2**31) - 1), (2**31) - 1), (-90, 90))

def decode_offset_corner_longitude_point_2_full(value):
    return int_to_float(value, (-((2**31) - 1), (2**31) - 1), (-180, 180))

def decode_offset_corner_latitude_point_3_full(value):
    return int_to_float(value, (-((2**31) - 1), (2**31) - 1), (-90, 90))

def decode_offset_corner_longitude_point_3_full(value):
    return int_to_float(value, (-((2**31) - 1), (2**31) - 1), (-180, 180))

def decode_offset_corner_latitude_point_4_full(value):
    return int_to_float(value, (-((2**31) - 1), (2**31) - 1), (-90, 90))

def decode_offset_corner_longitude_point_4_full(value):
    return int_to_float(value, (-((2**31) - 1), (2**31) - 1), (-180, 180))

def decode_platform_pitch_angle(byte_seq):
    value = int.from_bytes(byte_seq, byteorder='big', signed=True)
    return ((value / (2**15)) * 20) if value != -2**15 else float('NaN')

def decode_platform_roll_angle(byte_seq):
    value = int.from_bytes(byte_seq, byteorder='big', signed=True)
    return ((value / (2**15)) * 50) if value != -2**15 else float('NaN')

def decode_platform_angle_of_attack_full(value):
    return int_to_float(value, (-((2**31) - 1), (2**31) - 1), (-90, 90))

def decode_platform_sideslip_angle_full(value):
    return int_to_float(value, (-((2**31) - 1), (2**31) - 1), (-90, 90))

def decode_target_width_extended(value):
    return 'IMAPB'

def decode_density_altitude_extended(value):
    return 'IMAPB'

def decode_sensor_ellipsoid_height_extended(value):
    return 'IMAPB'

def decode_alternate_platform_ellipsoid_height_extended(value):
    return 'IMAPB'

def decode_rvt_local_set(value):
    """
    Decoder for Key 73: RVT Local Set.
    This field is used to embed an ST0806 RVT Local Set.
    Here we simply return the raw hex string.
    """
    return f"RVT Local Set: {value.hex()}"

def decode_image_horizon_pixel_pack(value):
    """
    Decoder for Key 81: Image Horizon Pixel Pack.
    Without detailed structure, we return the raw hex representation.
    If the structure is known, you could parse sub-fields here.
    """
    return f"Image Horizon Pixel Pack: {value.hex()}"

def decode_miis_core_identifier(value):
    """
    Decoder for Key 94: MIIS Core Identifier.
    Typically a 16-byte binary value.
    """
    return value.hex()

def decode_sar_motion_imagery_metadata(value):
    """
    Decoder for Key 95: SAR Motion Imagery Metadata.
    This is a nested local set (ST 1206). In this placeholder,
    we return the raw hex representation.
    """
    return f"SAR Motion Imagery Metadata: {value.hex()}"

def decode_reserved(value):
    """
    Generic decoder for reserved/future keys (97, 98, 99, 100, 101, 102).
    Returns the raw value as a hex string.
    """
    return f"Reserved (raw): {value.hex()}"

# Utility functions for conversions
def uint_to_float(value, domain, range_):
    raw_value = int.from_bytes(value, byteorder='big')
    return (raw_value - domain[0]) * (range_[1] - range_[0]) / (domain[1] - domain[0])

def int_to_float(value, domain, range_):
    raw_value = int.from_bytes(value, byteorder='big', signed=True)
    return (raw_value - domain[0]) * (range_[1] - range_[0]) / (domain[1] - domain[0])
