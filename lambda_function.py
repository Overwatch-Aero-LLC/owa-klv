import json
import boto3
import logging
import os
import io
from lib.klvParser import KLVParser

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')

# Corrected bucket name (bucket ONLY)
DESTINATION_BUCKET = 'fmv-test'

# Prefix for subfolder(s) inside bucket
DESTINATION_PREFIX = 'lambdaTest/output'
UAS_LDS_KEY = [6, 14, 43, 52, 2, 11, 1, 1, 14, 1, 3, 1, 1, 0, 0, 0]

TS_PACKET_SIZE = 188
SYNC_BYTE = 0x47
TARGET_PID = [0x101, 0x1f5, 0x1fe]  # This is the second stream

def extract_klv_payloads_from_ts(stream, ts_packet_size=TS_PACKET_SIZE, klv_pids=TARGET_PID, max_packets=None):
    klv_data = b""
    stream.seek(0)
    packet_count = 0
    while True:
        if max_packets and packet_count >= max_packets:
            break
        packet = stream.read(ts_packet_size)
        if not packet or len(packet) != ts_packet_size:
            break  # End of stream or incomplete packet

        # Check sync byte
        if packet[0] != SYNC_BYTE:
            continue

        # Parse header
        pid = ((packet[1] & 0x1F) << 8) | packet[2]

        if pid not in klv_pids:
            continue

        # Adaptation field control
        adaptation_field_control = (packet[3] >> 4) & 0x03
        payload_start = 4

        if adaptation_field_control in [2, 3]:  # Has adaptation field
            adaptation_field_length = packet[4]
            payload_start += 1 + adaptation_field_length

        if payload_start >= ts_packet_size:
            continue  # No payload

        payload = packet[payload_start:]
        klv_data += payload
        packet_count += 1
    return klv_data

FIELDS = [
    "Precision Time Stamp",
    "Frame Center Latitude",
    "Frame Center Longitude",
    "Offset Corner Latitude Point 1",
    "Offset Corner Longitude Point 1",
    "Offset Corner Latitude Point 2",
    "Offset Corner Longitude Point 2",
    "Offset Corner Latitude Point 3",
    "Offset Corner Longitude Point 3",
    "Offset Corner Latitude Point 4",
    "Offset Corner Longitude Point 4",
]

INTERVAL_SEC = 2.0  # You can adjust this as needed

def downsample_and_annotate(records):
    """
    Sort raw records by timestamp, then:
     - keep one packet per INTERVAL_SEC seconds
     - prune each to only the keys in FIELDS
     - skip packets where center lat/lon are both 0.0
    Returns a list of processed packet dicts.
    """
    sorted_recs = sorted(records, key=lambda r: float(r["Precision Time Stamp"]))
    output = []
    last_ts_s = None

    for pkt in sorted_recs:
        # Skip packets where both center lat and lon are 0.0
        if (
            float(pkt["Frame Center Latitude"]) == 0.0 and
            float(pkt["Frame Center Longitude"]) == 0.0
        ):
            continue

        ts_s = float(pkt["Precision Time Stamp"]) / 1000.0
        if last_ts_s is None or (ts_s - last_ts_s) >= INTERVAL_SEC:
            # prune to only needed fields
            pr = {k: pkt[k] for k in FIELDS}
            output.append(pr)
            last_ts_s = ts_s

    return output

def lambda_handler(event, context):
    logger.info("Event received: %s", json.dumps(event))

    try:
        source_bucket = event['Records'][0]['s3']['bucket']['name']
        source_key = event['Records'][0]['s3']['object']['key']
        logger.info(f"Source Bucket: {source_bucket}, File: {source_key}")
    except KeyError as e:
        logger.error("Event parsing error: %s", e)
        return {"statusCode": 400, "body": "Bad event data"}

    try:
        # Retrieve .ts file from the source bucket
        response = s3.get_object(Bucket=source_bucket, Key=source_key)
        raw_bytes = response['Body'].read()
        stream = io.BytesIO(raw_bytes)

        # Extract KLV data directly from the stream
        klv_data = extract_klv_payloads_from_ts(stream)

        logger.info(f"Extracted KLV data length: {len(klv_data)} bytes")

        # Parse the extracted KLV data
        parser = KLVParser(klv_data, UAS_LDS_KEY)
        parser.decode()
        result = parser.result

        logger.info(f"KLVParser result type: {type(result)}, length: {len(result) if hasattr(result, '__len__') else 'N/A'}")
        # Log a sample of the result
        if isinstance(result, dict):
            logger.info(f"KLVParser result sample (dict, first 2): {list(result.items())[:2]}")
        elif isinstance(result, list):
            logger.info(f"KLVParser result sample (list, first 2): {result[:2]}")
        else:
            logger.info(f"KLVParser result value: {result}")

        # --- Downsample, prune, and annotate before saving ---
        if isinstance(result, dict):
            records = list(result.values())
        elif isinstance(result, list):
            records = result
        else:
            logger.error("Unexpected result format from KLVParser")
            return {
                "statusCode": 500,
                "body": "Unexpected result format from KLVParser"
            }

        # Log how many records before filtering
        logger.info(f"Records before downsampling/filtering: {len(records)}")

        # Add logging inside downsample_and_annotate
        processed = []
        sorted_recs = sorted(records, key=lambda r: float(r["Precision Time Stamp"]))
        last_ts_s = None
        for pkt in sorted_recs:
            # Log if skipping due to 0.0 center
            if (
                float(pkt["Frame Center Latitude"]) == 0.0 and
                float(pkt["Frame Center Longitude"]) == 0.0
            ):
                logger.debug(f"Skipping packet with 0.0 center: {pkt}")
                continue

            ts_s = float(pkt["Precision Time Stamp"]) / 1000.0
            if last_ts_s is None or (ts_s - last_ts_s) >= INTERVAL_SEC:
                pr = {k: pkt[k] for k in FIELDS}
                processed.append(pr)
                last_ts_s = ts_s

        logger.info(f"Processed into {len(processed)} records")

        # Convert processed result to JSON
        json_result = json.dumps(processed, default=str, indent=2)

        ## Prepare the output JSON file name (replace .ts with .json)
        #output_filename = os.path.splitext(os.path.basename(source_key))[0] + '.json'

        # Construct full S3 key with prefix
        output_key = f"{DESTINATION_PREFIX}/sampled.json"

        # --- APPEND to existing JSON if it exists ---
        try:
            existing_obj = s3.get_object(Bucket=DESTINATION_BUCKET, Key=output_key)
            existing_data = json.loads(existing_obj['Body'].read())
            if not isinstance(existing_data, list):
                existing_data = []
        except s3.exceptions.NoSuchKey:
            existing_data = []
        except Exception as e:
            logger.warning(f"Could not load existing JSON, starting new. Reason: {e}")
            existing_data = []

        # Append new processed records
        existing_data.extend(processed)

        # Upload updated JSON to destination bucket
        json_result = json.dumps(existing_data, default=str, indent=2)
        s3.put_object(
            Bucket=DESTINATION_BUCKET,
            Key=output_key,
            Body=json_result.encode('utf-8'),
            ContentType='application/json'
        )

        logger.info(f"JSON appended and uploaded to s3://{DESTINATION_BUCKET}/{output_key}")

        return {
            "statusCode": 200,
            "body": f"File processed and JSON appended to s3://{DESTINATION_BUCKET}/{output_key}"
        }

    except Exception as e:
        logger.error("Error processing file: %s", e)
        return {
            "statusCode": 500,
            "body": str(e)
        }