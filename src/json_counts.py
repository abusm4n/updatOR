import os
import json
from pathlib import Path
from collections import defaultdict

def count_json_files(directory):
    """
    Count all .json files in a directory and its subdirectories.
    
    Args:
        directory (str): Path to the directory to search
        
    Returns:
        tuple: (total_count, list_of_file_paths)
    """
    json_count = 0
    json_files = []
    
    # Walk through all directories and files
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.json'):
                json_count += 1
                json_files.append(os.path.join(root, file))
    
    return json_count, json_files

def print_summary_by_folder(file_list):
    """Print summary of JSON files grouped by folder."""
    folder_counts = defaultdict(int)
    
    for file_path in file_list:
        folder = os.path.dirname(file_path)
        folder_counts[folder] += 1
    
    print("\nSummary by folder:")
    print("-" * 40)
    
    # Sort folders alphabetically
    for folder, count in sorted(folder_counts.items()):
        # Truncate long paths for display
        display_folder = folder
        if len(folder) > 50:
            display_folder = "..." + folder[-47:]
        print(f"{count:4d} files in: {display_folder}")
    
    return len(folder_counts)  # Return number of folders

def main():
    # Use a predefined directory path
    directory = "/home/ab/UpdatOR/cvelistV5/cves/2016"
    #directory = "/home/ab/UpdatOR/cvelistV5/cves/2017"
    #directory = "/home/ab/UpdatOR/cvelistV5/cves/2018"
    #directory = "/home/ab/UpdatOR/cvelistV5/cves/2019"
    #directory = "/home/ab/UpdatOR/cvelistV5/cves/2020"
    #directory = "/home/ab/UpdatOR/cvelistV5/cves/2021"
    #directory = "/home/ab/UpdatOR/cvelistV5/cves/2022"
    #directory = "/home/ab/UpdatOR/cvelistV5/cves/2023"
    #directory = "/home/ab/UpdatOR/cvelistV5/cves/2024"
    #directory = "/home/ab/UpdatOR/cvelistV5/cves/2025"


    # Check if directory exists
    if not os.path.exists(directory):
        print(f"Error: Directory '{directory}' does not exist!")
        return
    
    print(f"\nScanning directory: {directory}")
    print("=" * 60)
    
    # Count JSON files
    count, files = count_json_files(directory)
    
    # Print initial total
    print(f"Total JSON files found: {count}")
    
    # Show all files if count is reasonable
    if 0 < count <= 100:
        print("\nJSON Files:")
        print("-" * 40)
        for i, file_path in enumerate(files, 1):
            print(f"{i:4d}. {file_path}")
    elif count > 100:
        print(f"\n(Showing first 50 of {count} files)")
        print("-" * 40)
        for i, file_path in enumerate(files[:50], 1):
            print(f"{i:4d}. {file_path}")
        print(f"... and {count - 50} more files")
    
    # Print summary by folder
    if count > 0:
        print("\n" + "=" * 60)
        num_folders = print_summary_by_folder(files)
        
        # Print final total after folder summary
        print(f"\nFINAL TOTAL: {count} JSON files in {num_folders} folders")
        print("=" * 60)

if __name__ == "__main__":
    main()