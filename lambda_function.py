import json
import boto3
import logging
import os
from lib.klvParser import KLVParser
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3 = boto3.client('s3')

DESTINATION_BUCKET = 'fmv-test'
DESTINATION_PREFIX = 'lambdaTest/output'
DESTINATION_FILE = 'klvMetaData.json'

UAS_LDS_KEY = [6, 14, 43, 52, 2, 11, 1, 1, 14, 1, 3, 1, 1, 0, 0, 0]

TS_PACKET_SIZE = 188
SYNC_BYTE = 0x47
TARGET_PID = 0x101

def extract_klv_payloads_from_ts(stream):
    klv_data = b""
    while True:
        packet = stream.read(TS_PACKET_SIZE)
        if not packet or len(packet) != TS_PACKET_SIZE:
            break

        if packet[0] != SYNC_BYTE:
            continue

        pid = ((packet[1] & 0x1F) << 8) | packet[2]
        if pid != TARGET_PID:
            continue

        adaptation_field_control = (packet[3] >> 4) & 0x03
        payload_start = 4

        if adaptation_field_control in [2, 3]:
            adaptation_field_length = packet[4]
            payload_start += 1 + adaptation_field_length

        if payload_start >= TS_PACKET_SIZE:
            continue

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
        response = s3.get_object(Bucket=source_bucket, Key=source_key)
        klv_data = extract_klv_payloads_from_ts(response['Body'])

        parser = KLVParser(klv_data, UAS_LDS_KEY)
        parser.decode()
        result = parser.result

        # Retrieve existing JSON file from S3
        destination_key = f"{DESTINATION_PREFIX}/{DESTINATION_FILE}"

        try:
            existing_json_obj = s3.get_object(Bucket=DESTINATION_BUCKET, Key=destination_key)
            existing_json = existing_json_obj['Body'].read().decode('utf-8')
            json_data = json.loads(existing_json)
            logger.info("Existing JSON file found and loaded.")
        except ClientError as e:
            if e.response['Error']['Code'] == "NoSuchKey":
                json_data = []
                logger.info("No existing JSON file found. Creating new one.")
            else:
                raise e

        # Append new data
        json_data.append({
            "source_file": source_key,
            "parsed_data": result
        })

        # Convert back to JSON
        json_result = json.dumps(json_data, default=str, indent=2)

        # Upload updated JSON back to S3
        s3.put_object(
            Bucket=DESTINATION_BUCKET,
            Key=destination_key,
            Body=json_result.encode('utf-8'),
            ContentType='application/json'
        )

        logger.info(f"Updated JSON uploaded to s3://{DESTINATION_BUCKET}/{destination_key}")

        return {
            "statusCode": 200,
            "body": f"File processed and data appended to s3://{DESTINATION_BUCKET}/{destination_key}"
        }

    except Exception as e:
        logger.error("Error processing file: %s", e)
        return {
            "statusCode": 500,
            "body": str(e)
        }
