"""
false_negative_check.py

Random-sample false-negative audit for the update-related CVE dataset.

Approach
--------
The original keyword search used the following *primary* terms to retrieve
update-related CVEs:
    software update, firmware update, software upgrade, firmware upgrade,
    update process, upgrade process, downgrade, OTA update, over-the-air update

To estimate the false-negative rate we:
1. Build the set of CVE IDs already captured in the curated dataset
   (data/both/, data_fw/, data_sw/).
2. Define a set of *secondary* / *alternative* phrasing that plausibly
   describes update-related activity but is NOT in the primary keyword list
   (e.g. "apply patch", "push update", "install update", "reflash",
   "rollback mechanism", "FOTA", "remote update").
3. Scan the full CVE repository (cvelistV5/cves/) for CVEs that:
     (a) are NOT already in the curated dataset, AND
     (b) contain at least one secondary term.
   These are *candidate* false negatives.
4. Draw a stratified random sample of N_SAMPLE candidates and print their
   descriptions so they can be manually reviewed.
5. Report a summary: how many candidate FNs were found, what fraction of
   the un-captured CVEs they represent, and how many of the sampled ones
   appear genuinely update-related on manual inspection.
"""

import json
import os
import random
import re
import sys

# ──────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR        = os.path.join(BASE_DIR, "data")
# Folders containing the 892 *captured* update-related CVEs
CAPTURED_DIRS   = ["both", "data_fw", "data_sw"]
# Folder containing ALL CVEs (the ~243 k overall baseline)
OVERALL_DIR     = os.path.join(DATA_DIR, "overall")
N_SAMPLE        = 50          # number of candidate FNs to randomly inspect
RANDOM_SEED     = 42

# Primary keywords (already used in the original search — lower-cased)
PRIMARY_KEYWORDS = [
    "software update",
    "firmware update",
    "software upgrade",
    "firmware upgrade",
    "update process",
    "upgrade process",
    "downgrade",
    "ota update",
    "over-the-air update",
    "over-the-air",        # broader form
]

# Secondary / alternative terms that describe update-related activity
# but were NOT part of the original keyword list
SECONDARY_TERMS = [
    "apply.*patch",          # "apply a patch", "applying the patch"
    r"\bfota\b",             # Firmware Over The Air (acronym)
    r"\bswupdate\b",         # SWUpdate framework
    r"\bsw update\b",
    "install.*update",       # "installing an update"
    "push.*update",
    "remote update",
    "reflash",               # reflash firmware
    "re-flash",
    "flash.*firmware",
    "firmware flash",
    "rollback.*mechanism",
    "update mechanism",      # slightly different from "update process"
    "update package",
    "update server",
    "update image",
    "upgrade.*package",
    "upgrade.*image",
    "update integrity",
    "update verification",
    "secure.*boot.*update",
    "bootloader.*update",
]

# Pre-compile secondary patterns
SECONDARY_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SECONDARY_TERMS]

# ──────────────────────────────────────────────────────────────────
# Step 1 – collect captured CVE IDs (update-related curated set)
# ──────────────────────────────────────────────────────────────────
def collect_curated_ids():
    captured = set()
    for subdir in CAPTURED_DIRS:
        folder = os.path.join(DATA_DIR, subdir)
        if not os.path.isdir(folder):
            continue
        for fname in os.listdir(folder):
            if fname.endswith(".json"):
                captured.add(fname.replace(".json", ""))
    return captured


# ──────────────────────────────────────────────────────────────────
# Step 2 – extract description text from a CVE JSON record
# ──────────────────────────────────────────────────────────────────
def get_description(cve_path):
    try:
        with open(cve_path, encoding="utf-8") as fh:
            data = json.load(fh)
        descs = (data.get("containers", {})
                     .get("cna", {})
                     .get("descriptions", []))
        texts = [d.get("value", "") for d in descs if d.get("lang", "").startswith("en")]
        return " ".join(texts)
    except Exception:
        return ""


# ──────────────────────────────────────────────────────────────────
# Step 3 – scan overall dataset for candidate false negatives
# ──────────────────────────────────────────────────────────────────
def has_secondary_term(text):
    for pat in SECONDARY_PATTERNS:
        if pat.search(text):
            return True
    return False


def has_primary_keyword(text):
    tl = text.lower()
    return any(kw in tl for kw in PRIMARY_KEYWORDS)


def scan_overall(captured_ids):
    """Return list of (cve_id, description, matched_term) for candidate FNs.

    Scans data/overall/ — the full ~243 k baseline — and flags CVEs that:
      (a) are NOT in the captured update-related set, AND
      (b) do NOT contain any primary keyword (which would have been retrieved
          and then excluded by manual review), AND
      (c) DO contain at least one secondary / alternative update-related term.
    """
    candidates = []
    total_scanned = 0
    for year_dir in sorted(os.listdir(OVERALL_DIR)):
        year_path = os.path.join(OVERALL_DIR, year_dir)
        if not os.path.isdir(year_path):
            continue
        for batch_dir in sorted(os.listdir(year_path)):
            batch_path = os.path.join(year_path, batch_dir)
            if not os.path.isdir(batch_path):
                continue
            for fname in os.listdir(batch_path):
                if not fname.endswith(".json"):
                    continue
                cve_id = fname.replace(".json", "")
                # Skip already-captured update-related CVEs
                if cve_id in captured_ids:
                    continue
                total_scanned += 1
                desc = get_description(os.path.join(batch_path, fname))
                if not desc:
                    continue
                # Skip if a primary keyword is present: those were retrieved
                # by the original search and excluded during manual review
                # (i.e., they are known false positives, not false negatives)
                if has_primary_keyword(desc):
                    continue
                if has_secondary_term(desc):
                    for pat in SECONDARY_PATTERNS:
                        m = pat.search(desc)
                        if m:
                            candidates.append((cve_id, desc, m.group()))
                            break
    return candidates, total_scanned


# ──────────────────────────────────────────────────────────────────
# Step 4 – sample and display
# ──────────────────────────────────────────────────────────────────
def print_sample(sample):
    print("\n" + "=" * 70)
    print(f"RANDOM SAMPLE OF {len(sample)} CANDIDATE FALSE NEGATIVES")
    print("=" * 70)
    for i, (cve_id, desc, matched) in enumerate(sample, 1):
        print(f"\n[{i:02d}] {cve_id}  (matched: '{matched}')")
        print("-" * 60)
        # Truncate long descriptions for readability
        print(desc[:500] + ("…" if len(desc) > 500 else ""))


# ──────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────
def main():
    random.seed(RANDOM_SEED)

    print("Step 1: Collecting captured (update-related) CVE IDs …")
    captured_ids = collect_curated_ids()
    print(f"  → {len(captured_ids)} CVEs in the curated update-related dataset.")

    print("\nStep 2: Scanning overall CVE dataset for candidate false negatives …")
    print("  (This may take a few minutes on a large repository.)")
    candidates, total_scanned = scan_overall(captured_ids)

    print(f"\n  → Scanned {total_scanned:,} non-captured CVEs from the overall dataset.")
    print(f"  → Found {len(candidates):,} candidate false negatives "
          f"({100*len(candidates)/max(total_scanned,1):.2f}% of scanned).")

    if not candidates:
        print("\nNo candidate false negatives found. "
              "The keyword set appears to provide good coverage.")
        return

    # Stratified sample: up to N_SAMPLE
    n = min(N_SAMPLE, len(candidates))
    sample = random.sample(candidates, n)

    print_sample(sample)

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Captured update-related CVEs : {len(captured_ids):,}")
    print(f"  Non-captured CVEs scanned    : {total_scanned:,}")
    print(f"  Candidate false negatives    : {len(candidates):,}")
    print(f"  Candidate FN rate (upper bd) : {100*len(candidates)/max(total_scanned,1):.2f}%")
    print(f"  Random sample size           : {n}")
    print(f"\nNote: 'Candidate FN' means the CVE contains secondary update-related")
    print(f"terminology but was NOT retrieved by the primary keyword search.")
    print(f"Manual inspection of the sample above is needed to determine how")
    print(f"many are genuinely update-related (true false negatives).")

    # Save candidate list to CSV for further manual inspection
    out_csv = os.path.join(BASE_DIR, "src", "false_negative_candidates.csv")
    with open(out_csv, "w", encoding="utf-8") as fh:
        fh.write("cve_id,matched_term,description\n")
        for cve_id, desc, matched in candidates:
            safe_desc = desc.replace('"', "'").replace("\n", " ")[:300]
            fh.write(f'"{cve_id}","{matched}","{safe_desc}"\n')
    print(f"\nFull candidate list saved to: {out_csv}")


if __name__ == "__main__":
    main()
