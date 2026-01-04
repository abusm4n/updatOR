import shutil
from pathlib import Path

# Paths
names_dir = Path("./data/datafw")
cvelist_dir = Path("~/UpdatOR/cvelistV5").expanduser()
dest_dir = Path("./data/fw")

# Create destination directory
dest_dir.mkdir(parents=True, exist_ok=True)

# Step 1: Collect target JSON filenames
target_names = {
    f.name for f in names_dir.iterdir()
    if f.is_file() and f.suffix == ".json"
}

print(f"Target JSON files: {len(target_names)}")

# Step 2: Index CVEList recursively
cve_index = {}
for json_file in cvelist_dir.rglob("*.json"):
    # First match wins (CVE filenames are unique in practice)
    cve_index.setdefault(json_file.name, json_file)

print(f"Indexed {len(cve_index)} JSON files from CVEList")

# Step 3: Copy matching files
copied = 0
missing = []

for name in target_names:
    if name in cve_index:
        src = cve_index[name]
        dst = dest_dir / name
        shutil.copy2(src, dst)
        copied += 1
    else:
        missing.append(name)

# Report
print(f"\nCopied: {copied}")
print(f"Missing: {len(missing)}")

if missing:
    print("\nMissing files:")
    for m in missing:
        print(f"  {m}")
