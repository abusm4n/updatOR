import json
from collections import Counter
import os

# Function to load JSON file
def load_json_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

# Function to extract severity metrics (considering only CVSS V3 if present, else CVSS V2)
def extract_severity(cve_data):
    severities = []

    # Check if impact data is a dictionary
    impact_data = cve_data.get('impact', {})
    if isinstance(impact_data, dict):
        # Extract CVSS V3 severity
        cvss_v3 = impact_data.get('baseMetricV3', {}).get('cvssV3', {})
        if cvss_v3:
            base_score = cvss_v3.get('baseScore')
            if base_score is not None:
                if base_score >= 9.0:
                    severities.append("Critical")
                elif base_score >= 7.0:
                    severities.append("High")
                elif base_score >= 4.0:
                    severities.append("Medium")
                else:
                    severities.append("Low")
        else:
            # Extract CVSS V2 severity if CVSS V3 is not present
            cvss_v2 = impact_data.get('baseMetricV2', {}).get('cvssV2', {})
            if cvss_v2:
                base_score = cvss_v2.get('baseScore')
                if base_score is not None:
                    if base_score >= 7.0:
                        severities.append("High")
                    elif base_score >= 4.0:
                        severities.append("Medium")
                    else:
                        severities.append("Low")
    
    return severities

# Path to dataset folder
dataset_folder = './dataset_sw'

# Get list of JSON files in the dataset folder
json_files = [file for file in os.listdir(dataset_folder) if file.endswith('.json')]

# Initialize counter to accumulate severity counts
total_severity_counter = Counter()

# Process each JSON file and accumulate severity counts
for file_name in json_files:
    file_path = os.path.join(dataset_folder, file_name)
    cve_json = load_json_file(file_path)

    # Skip files that couldn't be loaded
    if cve_json is None:
        continue

    # Check if the impact field is a list and skip if so
    if isinstance(cve_json.get('impact'), list):
        print(f"Skipping file {file_name} as its 'impact' field is a list")
        continue

    severities = extract_severity(cve_json)
    
    # Initialize counter for current file
    severity_counter = Counter()

    # Count severity metrics for current file
    for severity in severities:
        severity_counter[severity] += 1

    # Accumulate counts to total counter
    total_severity_counter += severity_counter

# Print the total frequency of each severity type
print("Total Severity Frequency:")
for severity, count in total_severity_counter.items():
    print(f"{severity}: {count}")
