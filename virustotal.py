# This Python script reads a CSV file containing file hashes, queries the VirusTotal API for scan reports, and sorts the entries into two separate CSV files: one for malicious files and one for non-malicious files. It checks for malware detections by specific antivirus engines (TrendMicro, Kaspersky, McAfee, Avast). The script includes validation for MD5, SHA1, and SHA256 file hashes, handles API rate limits, and skips invalid or incomplete rows.

import requests
import csv
import time
import logging
import re

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Set your VirusTotal API key here
API_KEY = 'e3627894a47f1f3b9568c6b68a4102a53edd81b99bebb21dec86646015b542d5'

# VirusTotal URL for file scanning/reporting
VIRUSTOTAL_URL = 'https://www.virustotal.com/vtapi/v2/file/report'

# Antivirus engines you are checking for
engines_to_check = ['TrendMicro', 'Kaspersky', 'McAfee', 'Avast', 'F-Secure', 'Symantec']

# Function to query VirusTotal and get the scan report
def get_virus_total_report(resource):
    params = {'apikey': API_KEY, 'resource': resource}
    try:
        response = requests.get(VIRUSTOTAL_URL, params=params)
        response.raise_for_status()  # This will raise an exception for HTTP errors (4xx, 5xx)
        
        if response.status_code == 204:
            logging.error(f"Rate limit exceeded for resource {resource}. Retrying after delay...")
            time.sleep(60)  # Wait for a minute if rate limit is exceeded
            return None
        elif response.status_code == 403:
            logging.error(f"Access to the API denied for resource {resource}. Check your API key or permissions.")
            return None
        elif response.status_code == 400:
            logging.error(f"Bad request for resource {resource}. It may not be a valid file hash.")
            return None
        else:
            return response.json() if response.text else None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying VirusTotal for resource {resource}: {e}")
        return None

# Function to check if a file is malicious based on antivirus engines' reports
def is_malicious(report):
    if 'scans' not in report:
        logging.warning("No scan data found in the report.")
        return False

    scans = report['scans']
    for engine in engines_to_check:
        if scans.get(engine, {}).get('detected', False):
            return True
    return False

# Function to validate if the input string looks like a valid MD5, SHA1, or SHA256 file hash
def is_valid_hash(file_hash):
    # File hash must be 32 (MD5), 40 (SHA1), or 64 (SHA256) characters long and contain only hexadecimal characters
    return bool(re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', file_hash))

# Provide the full path to your input CSV file
input_file_path = '/Users/obicass/Downloads/download.csv'

# Open the CSV file to read the entries
with open(input_file_path, mode='r') as infile:
    reader = csv.reader(infile)
    headers = next(reader)  # Read the headers

    # Open two new CSV files for malicious and non-malicious outputs
    with open('malicious.csv', mode='w', newline='') as malicious_file, open('non_malicious.csv', mode='w', newline='') as non_malicious_file:
        malicious_writer = csv.writer(malicious_file)
        non_malicious_writer = csv.writer(non_malicious_file)

        # Write headers to the new files
        malicious_writer.writerow(headers)
        non_malicious_writer.writerow(headers)

        # Iterate over each entry in the input CSV
        for row in reader:
            # Skip empty rows
            if not row or len(row) < 2:
                logging.warning("Skipping empty or incomplete row.")
                continue

            # Clean up the file hash by stripping extra spaces or quotes
            file_hash = row[3].strip().replace('"', '')  # Assuming the file hash is in the second column
            logging.info(f"Checking file hash: {file_hash}")

            # Validate if the file hash is correct
            if not is_valid_hash(file_hash):
                logging.error(f"Invalid file hash format: {file_hash}")
                continue  # Skip invalid hash

            # Get the VirusTotal report for the file hash
            report = get_virus_total_report(file_hash)

            # Check if the API returned a valid response
            if report is None:
                logging.error(f"Skipping file hash {file_hash} due to API error.")
                continue

            # Handle the case when a report isn't available
            if report.get('response_code') != 1:
                logging.warning(f"No report available for file hash: {file_hash}")
                non_malicious_writer.writerow(row)
                continue

            # Add a delay between requests to stay within API rate limits
            time.sleep(15)  # Adjust the sleep time to match API rate limits

            # Check if the file is malicious based on antivirus engines' detections
            if is_malicious(report):
                logging.info(f"File hash {file_hash} is malicious.")
                malicious_writer.writerow(row)
            else:
                logging.info(f"File hash {file_hash} is non-malicious.")
                non_malicious_writer.writerow(row)

print("CSV sorting complete!")
