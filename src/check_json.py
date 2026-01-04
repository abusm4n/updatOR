import os
import sys

def check_json_files(folder_x, folder_y, folder_z):
    """
    Check if JSON files in folder_x exist in folder_y and folder_z.
    Print the names of JSON files that don't exist in both folder_y and folder_z.
    """
    
    # Check if all folders exist
    for folder in [folder_x, folder_y, folder_z]:
        if not os.path.isdir(folder):
            print(f"Error: Folder '{folder}' does not exist.")
            return
    
    # Get all JSON files from folder_x
    try:
        x_files = [f for f in os.listdir(folder_x) if f.lower().endswith('.json')]
    except PermissionError:
        print(f"Error: No permission to read folder '{folder_x}'.")
        return
    
    print(f"Found {len(x_files)} JSON files in '{folder_x}'")
    
    # Get all JSON files from folder_y and folder_z
    y_files = set()
    z_files = set()
    
    try:
        for folder, file_set in [(folder_y, y_files), (folder_z, z_files)]:
            for f in os.listdir(folder):
                if f.lower().endswith('.json'):
                    file_set.add(f)
    except PermissionError as e:
        print(f"Error: No permission to read one of the comparison folders.")
        return
    
    # Check which files from folder_x don't exist in folder_y and folder_z
    missing_files = []
    for file_name in x_files:
        if file_name not in y_files and file_name not in z_files:
            missing_files.append(file_name)
    
    # Print results
    if missing_files:
        print("\nFiles in folder_x that don't exist in folder_y OR folder_z:")
        print("=" * 60)
        for file_name in missing_files:
            print(f"  - {file_name}")
        print(f"\nTotal missing files: {len(missing_files)}")
    else:
        print("\nAll JSON files from folder_x exist in either folder_y or folder_z.")

def main():
    # You can modify these folder paths as needed
    folder_x = "./data/both"  # Folder containing source JSON files
    folder_y = "./data/fw"  # First comparison folder
    folder_z = "./data/sw"  # Second comparison folder
    
    # Alternative: Use command-line arguments
    if len(sys.argv) == 4:
        folder_x, folder_y, folder_z = sys.argv[1], sys.argv[2], sys.argv[3]
    
    check_json_files(folder_x, folder_y, folder_z)

if __name__ == "__main__":
    main()