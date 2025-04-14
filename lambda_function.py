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

        # Convert parsed result to JSON
        json_result = json.dumps(result, default=str, indent=2)

        # Prepare the output JSON file name (replace .ts with .json)
        output_filename = os.path.splitext(os.path.basename(source_key))[0] + '.json'

        # Construct full S3 key with prefix
        output_key = f"{DESTINATION_PREFIX}/{output_filename}"

        # Upload JSON to destination bucket
        s3.put_object(
            Bucket=DESTINATION_BUCKET,
            Key=output_key,
            Body=json_result.encode('utf-8'),
            ContentType='application/json'
        )

        logger.info(f"JSON uploaded to s3://{DESTINATION_BUCKET}/{output_key}")

        return {
            "statusCode": 200,
            "body": f"File processed and JSON uploaded to s3://{DESTINATION_BUCKET}/{output_key}"
        }

    except Exception as e:
        logger.error("Error processing file: %s", e)
        return {
            "statusCode": 500,
            "body": str(e)
        }