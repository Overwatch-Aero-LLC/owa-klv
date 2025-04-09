import json
import boto3
import logging
import os
import time
import csv

from lib.klvParser import KLVParser

logger = logging.getLogger()
logger.setLevel(logging.INFO)

UAS_LDS_KEY = [6, 14, 43, 52, 2, 11, 1, 1, 14, 1, 3, 1, 1, 0, 0, 0]

def lambda_handler(event, context):
    logger.info("Event received: %s", json.dumps(event))

    # Extract bucket and file information from event
    try:
        bucket = event['Records'][0]['s3']['bucket']['name']
        key = event['Records'][0]['s3']['object']['key']
        logger.info(f"Bucket: {bucket}, File: {key}")
    except KeyError as e:
        logger.error("Event parsing error: %s", e)
        return {"statusCode": 400, "body": "Bad event data"}

    # For local testing, read directly from the file system instead of S3
    local_file_path = os.path.join(os.getcwd(), key)

    try:
        with open(local_file_path, 'rb') as f:
            raw_binary = f.read()
        
        parser = KLVParser(raw_binary, UAS_LDS_KEY)
        parser.decode()

        # Output the results to your logs (or write to your output folder)
        result = parser.result
        logger.info("Parsed data: %s", json.dumps(result, indent=2, default=str))

        return {"statusCode": 200, "body": json.dumps(result, default=str)}

    except Exception as e:
        logger.error("Error processing file: %s", e)
        return {"statusCode": 500, "body": str(e)}
