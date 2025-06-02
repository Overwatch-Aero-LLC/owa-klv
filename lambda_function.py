import json
import boto3
import logging
import os
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
TARGET_PID = 0x101  # This is the second stream

def extract_klv_payloads_from_ts(stream):
    klv_data = b""
    while True:
        packet = stream.read(TS_PACKET_SIZE)
        if not packet or len(packet) != TS_PACKET_SIZE:
            break  # End of stream or incomplete packet

        # Check sync byte
        if packet[0] != SYNC_BYTE:
            continue

        # Parse header
        pid = ((packet[1] & 0x1F) << 8) | packet[2]

        if pid != TARGET_PID:
            continue

        # Adaptation field control
        adaptation_field_control = (packet[3] >> 4) & 0x03
        payload_start = 4

        if adaptation_field_control in [2, 3]:  # Has adaptation field
            adaptation_field_length = packet[4]
            payload_start += 1 + adaptation_field_length

        if payload_start >= TS_PACKET_SIZE:
            continue  # No payload

        payload = packet[payload_start:]
        klv_data += payload
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

def packet_bbox(pkt):
    """
    Compute the absolute bounding box (min_lat, max_lat, min_lon, max_lon)
    for a single packet, given its center and corner offsets.
    """
    c_lat = pkt["Frame Center Latitude"]
    c_lon = pkt["Frame Center Longitude"]
    lats = [pkt[f"Offset Corner Latitude Point {i}"] for i in range(1, 5)]
    lons = [pkt[f"Offset Corner Longitude Point {i}"] for i in range(1, 5)]
    abs_lats = [c_lat + d for d in lats]
    abs_lons = [c_lon + d for d in lons]
    return min(abs_lats), max(abs_lats), min(abs_lons), max(abs_lons)

def downsample_and_annotate(records):
    """
    Sort raw records by timestamp, then:
     - keep one packet per INTERVAL_SEC seconds
     - prune each to only the keys in FIELDS
     - annotate each with min_lat, max_lat, min_lon, max_lon
    Returns a list of processed packet dicts.
    """
    # sort by Precision Time Stamp (ms)
    sorted_recs = sorted(records, key=lambda r: float(r["Precision Time Stamp"]))
    output = []
    last_ts_s = None

    for pkt in sorted_recs:
        ts_s = float(pkt["Precision Time Stamp"]) / 1000.0
        if last_ts_s is None or (ts_s - last_ts_s) >= INTERVAL_SEC:
            # prune to only needed fields
            pr = {k: pkt[k] for k in FIELDS}
            # compute and attach bbox
            min_lat, max_lat, min_lon, max_lon = packet_bbox(pkt)
            pr.update({
                "min_lat": min_lat,
                "max_lat": max_lat,
                "min_lon": min_lon,
                "max_lon": max_lon
            })
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
        
        # Extract KLV data directly from the stream
        klv_data = extract_klv_payloads_from_ts(response['Body'])

        # Parse the extracted KLV data
        parser = KLVParser(klv_data, UAS_LDS_KEY)
        parser.decode()
        result = parser.result

        # --- NEW: Downsample, prune, and annotate before saving ---
        # If result is a dict of packets, convert to list
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

        processed = downsample_and_annotate(records)
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