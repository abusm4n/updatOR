import json
import os

# Function to load JSON file
def load_json_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

# Function to check for keywords in the JSON file descriptions
def contains_keywords(cve_data, keywords):
    # Extract the descriptions list from the 'containers.cna.descriptions' field
    descriptions = cve_data.get('containers', {}).get('cna', {}).get('descriptions', [])
    
    for item in descriptions:
        text = item.get('value', '').lower()  # Extract the description text
        # Check if any keyword is present in the text
        if any(keyword.lower() in text for keyword in keywords):
            return True
    return False

# Path to dataset folder
dataset_folder = './dataset_sw'

# Keywords to search for exmaple:
keywords = ["software update", "firmware update", "OTA", "upgrade process", "over-the-air"]

# Get list of JSON files in the dataset folder
json_files = [file for file in os.listdir(dataset_folder) if file.endswith('.json')]

# List to keep track of files containing the keywords
files_with_keywords = []

# Process each JSON file to check for keywords
for file_name in json_files:
    file_path = os.path.join(dataset_folder, file_name)
    cve_json = load_json_file(file_path)

    # Skip files that couldn't be loaded
    if cve_json is None:
        continue

    # Check for keywords in the descriptions field
    if contains_keywords(cve_json, keywords):
        files_with_keywords.append(file_name)

# Sort the list of files in ascending order
files_with_keywords.sort()

# Print the names of the files containing the keywords
print("Files containing the keywords (sorted in ascending order):")
for file_name in files_with_keywords:
    print(file_name)
