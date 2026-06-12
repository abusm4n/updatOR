"""
Run description-only classification counts and CWE extraction for the full
overall CVE dataset (242k CVEs), reusing the existing enhanced classification
from classification_overall/target-system.csv to avoid re-running the slow
enhanced classifier.

Outputs to: classification_overall/
"""
from __future__ import annotations

import csv
import json
import re
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

# ── constants ──────────────────────────────────────────────────────────────
DATA_DIR = Path("data/overall")
ENHANCED_CSV = Path("classification_overall/target-system.csv")
OUTPUT_DIR = Path("classification_overall")
TOP_N = 10
N_WORKERS = 8

FIVE_CLASSES = ["Home", "SCADA", "Enterprise", "Mobile", "PC"]
ALL_CLASSES = FIVE_CLASSES + ["Other"]

CLASS_PALETTE = {
    "Home": "#2A9D8F", "SCADA": "#C98A00", "Enterprise": "#5B6C8F",
    "Mobile": "#D96C54", "PC": "#4C78A8", "Other": "#A06A3A",
}

PATTERNS = {
    "Home": [
        r"smart\s+(home|thermostat|bulb|lock|speaker|tv|plug|camera|doorbell)",
        r"iot\s+device", r"connected\s+device", r"home\s+automation",
        r"\b(router|wifi|wireless)\s+(router|access\s+point|device)",
        r"\b(tplink|d-link|asus|netgear|linksys|nest|ring|arlo|wyze|roku)\b",
        r"security\s+camera", r"ip\s+camera", r"baby\s+monitor", r"smart\s+tv",
        r"streaming\s+device", r"gaming\s+console", r"\b(soho|home\s+router)\b",
        r"home\s+camera", r"home\s+security\s+camera", r"home\s+surveillance",
        r"yi", r"TP-Link ",
    ],
    "SCADA": [
        r"\b(scada|ics|plc|hmi|rtu|dcs)\b", r"industrial\s+control",
        r"process\s+control", r"supervisory\s+control", r"power\s+(grid|plant|station)",
        r"water\s+treatment", r"\b(oil|gas)\s+.*\s+(plant|refinery|pipeline)",
        r"medical\s+device", r"patient\s+monitor", r"hospital\s+equipment",
        r"\b(manufacturing|factory|plant)\b", r"\b(automotive|vehicle|car)\b",
        r"engine\s+control",
    ],
    "Enterprise": [
        r"enterprise\s+(network|system|software|application)",
        r"business\s+(network|application)", r"corporate\s+(network|environment)",
        r"cloud\s+(service|infrastructure|platform)", r"data\s+center",
        r"server\s+(software|application|side|hardware)",
        r"\b(switch|firewall|vpn|load\s+balancer)\b",
        r"\b(cisco|juniper|paloalto|fortinet|vmware|oracle|sap|microsoft\s+server)\b",
        r"storage\s+system", r"\b(nas|san)\b", r"local area",
        r"Operational Technology", r"Information Technology",
    ],
    "Mobile": [
        r"\b(android|ios|iphone|ipad|smartphone|tablet)\b",
        r"mobile\s+(device|phone|application|app|os)",
        r"google\s+play", r"app\s+store",
        r"\b(smartwatch|wearable|fitness\s+tracker)\b",
        r"\b(5g|lte|cellular)\b",
    ],
    "PC": [
        r"\b(pc|computer|desktop|laptop|notebook)\b", r"personal\s+computer",
        r"\b(windows|linux|macos|ubuntu|debian|centos|red\s+hat)\b",
        r"operating\s+system",
        r"\b(bios|uefi|cpu|gpu|ram|ssd|hard\s+drive|motherboard)\b",
        r"\b(microsoft\s+office|adobe|antivirus|browser)\b",
        r"\b(intel\s+nuc|chrome\s+os)\b", r"mac",
    ],
}


# ── classifier ─────────────────────────────────────────────────────────────
def classify_description_only(description: str) -> str:
    desc = description.lower()
    scores: dict[str, int] = {}
    for category, regex_list in PATTERNS.items():
        score = 0
        for pattern in regex_list:
            matches = re.findall(pattern, desc, flags=re.IGNORECASE)
            if matches:
                score += len(matches) * (3 if "\\s" in pattern else 2)
        if score > 0:
            scores[category] = score
    if scores:
        best, best_score = max(scores.items(), key=lambda x: x[1])
        if best_score >= 2:
            return best
    return "Other"


def extract_description(cve_json: dict) -> str:
    try:
        descs = cve_json["containers"]["cna"].get("descriptions", [])
        if descs:
            return descs[0].get("value", "")
    except (KeyError, IndexError, TypeError):
        pass
    try:
        for item in cve_json["containers"].get("adp", []):
            descs = item.get("descriptions", [])
            if descs:
                return descs[0].get("value", "")
    except (KeyError, IndexError, TypeError):
        pass
    return ""


def extract_cwes(cve_json: dict) -> dict[str, str]:
    result: dict[str, str] = {}
    containers = cve_json.get("containers", {})
    groups = list(containers.get("cna", {}).get("problemTypes", []))
    for adp in containers.get("adp", []):
        groups.extend(adp.get("problemTypes", []))
    for group in groups:
        for desc in group.get("descriptions", []):
            cwe_id = desc.get("cweId", "").strip()
            if not cwe_id or not cwe_id.startswith("CWE-"):
                continue
            name = desc.get("description", "").strip() or "Unknown"
            if cwe_id not in result or result[cwe_id] == "Unknown":
                result[cwe_id] = name
    return result


# ── per-file workers ────────────────────────────────────────────────────────
def _process_file_desc_only(path: str) -> str:
    """Return description-only class label for one JSON file."""
    try:
        with open(path, encoding="utf-8") as f:
            cve = json.load(f)
        desc = extract_description(cve)
        if not desc.strip():
            return ""
        return classify_description_only(desc)
    except Exception:
        return ""


def _process_file_cwe(args: tuple[str, str]) -> tuple[str, dict[str, str]]:
    """Return (cve_class, cwe_details) for one JSON file (non-Other only)."""
    path, cve_class = args
    try:
        with open(path, encoding="utf-8") as f:
            cve = json.load(f)
        cwes = extract_cwes(cve)
        return cve_class, cwes
    except Exception:
        return cve_class, {}


# ── main ───────────────────────────────────────────────────────────────────
def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # ── Step 1: load existing enhanced classification ─────────────────────
    print("Loading existing enhanced classification CSV …")
    enhanced_df = pd.read_csv(ENHANCED_CSV)
    enhanced_counts: Counter = Counter(enhanced_df["class"].tolist())
    total_enhanced = len(enhanced_df)
    print(f"  Enhanced: {total_enhanced:,} CVEs loaded")
    for cls in ALL_CLASSES:
        n = enhanced_counts.get(cls, 0)
        print(f"    {cls:12s} {n:7,}  ({n/total_enhanced*100:.1f}%)")

    # ── Step 2: description-only counts (parallel) ────────────────────────
    print("\nComputing description-only counts (parallel) …")
    all_json = sorted(DATA_DIR.rglob("*.json"))
    print(f"  {len(all_json):,} JSON files found")

    desc_counts: Counter = Counter()
    chunk = 2000
    completed = 0
    with ProcessPoolExecutor(max_workers=N_WORKERS) as pool:
        futures = {pool.submit(_process_file_desc_only, str(p)): p for p in all_json}
        for future in as_completed(futures):
            label = future.result()
            if label:
                desc_counts[label] += 1
            else:
                desc_counts["Other"] += 1
            completed += 1
            if completed % chunk == 0:
                print(f"  … {completed:,}/{len(all_json):,}", flush=True)

    total_desc = sum(desc_counts.values())
    print(f"\nDescription-only results ({total_desc:,} CVEs):")
    for cls in ALL_CLASSES:
        n = desc_counts.get(cls, 0)
        print(f"  {cls:12s} {n:7,}  ({n/total_desc*100:.1f}%)")

    # ── Step 3: CWE extraction for non-Other CVEs (parallel) ──────────────
    print("\nExtracting CWEs for non-Other CVEs …")
    cve_id_to_class = dict(zip(enhanced_df["id"], enhanced_df["class"]))
    non_other = {cve_id: cls for cve_id, cls in cve_id_to_class.items() if cls in FIVE_CLASSES}
    print(f"  {len(non_other):,} non-Other CVEs to process")

    # build path lookup from CVE ID
    id_to_path = {p.stem: str(p) for p in all_json}

    class_cwe_counts: dict[str, Counter] = {cls: Counter() for cls in FIVE_CLASSES}
    class_cwe_names: dict[str, dict[str, str]] = {cls: {} for cls in FIVE_CLASSES}

    task_args = [(id_to_path[cve_id], cls) for cve_id, cls in non_other.items() if cve_id in id_to_path]
    print(f"  {len(task_args):,} tasks queued")

    completed = 0
    with ProcessPoolExecutor(max_workers=N_WORKERS) as pool:
        futures = {pool.submit(_process_file_cwe, arg): arg for arg in task_args}
        for future in as_completed(futures):
            cve_class, cwes = future.result()
            for cwe_id, cwe_name in cwes.items():
                class_cwe_counts[cve_class][cwe_id] += 1
                if cwe_id not in class_cwe_names[cve_class] or class_cwe_names[cve_class][cwe_id] == "Unknown":
                    class_cwe_names[cve_class][cwe_id] = cwe_name
            completed += 1
            if completed % 5000 == 0:
                print(f"  … {completed:,}/{len(task_args):,}", flush=True)

    # ── Step 4: print top weaknesses ──────────────────────────────────────
    print("\nTop weaknesses per class:")
    for cls in FIVE_CLASSES:
        print(f"\n[{cls}] {enhanced_counts.get(cls,0):,} CVEs")
        for cwe_id, count in class_cwe_counts[cls].most_common(TOP_N):
            name = class_cwe_names[cls].get(cwe_id, "Unknown")
            print(f"  {cwe_id:12s} {count:5,}  {name[:60]}")

    # ── Step 5: save CSV outputs ──────────────────────────────────────────
    # description-only distribution
    desc_rows = [{"class": cls, "count": desc_counts.get(cls, 0),
                  "pct": round(desc_counts.get(cls, 0) / total_desc * 100, 1)}
                 for cls in ALL_CLASSES]
    pd.DataFrame(desc_rows).to_csv(OUTPUT_DIR / "description_only_distribution.csv", index=False)

    # top weaknesses
    cwe_rows = []
    for cls in FIVE_CLASSES:
        for rank, (cwe_id, count) in enumerate(class_cwe_counts[cls].most_common(TOP_N), 1):
            cwe_rows.append({"class": cls, "rank": rank, "cwe_id": cwe_id,
                              "cwe_name": class_cwe_names[cls].get(cwe_id, "Unknown"),
                              "count": count})
    pd.DataFrame(cwe_rows).to_csv(OUTPUT_DIR / "top_weaknesses_overall.csv", index=False)

    # summary JSON
    summary = {
        "total_enhanced": total_enhanced,
        "total_desc_only": total_desc,
        "enhanced_counts": {cls: int(enhanced_counts.get(cls, 0)) for cls in ALL_CLASSES},
        "desc_only_counts": {cls: int(desc_counts.get(cls, 0)) for cls in ALL_CLASSES},
        "top_weaknesses": {
            cls: [{"cwe_id": cid, "count": int(cnt),
                   "cwe_name": class_cwe_names[cls].get(cid, "Unknown")}
                  for cid, cnt in class_cwe_counts[cls].most_common(TOP_N)]
            for cls in FIVE_CLASSES
        },
    }
    with open(OUTPUT_DIR / "overall_analysis_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    # ── Step 6: plots ─────────────────────────────────────────────────────
    _plot_distribution(desc_counts, total_desc,
                       OUTPUT_DIR / "overall_description_only_distribution.pdf",
                       "Description-Only Distribution (Overall, 243k CVEs)",
                       "Rule-based labels from description text only.")
    _plot_distribution(enhanced_counts, total_enhanced,
                       OUTPUT_DIR / "overall_enhanced_distribution.pdf",
                       "Enhanced Distribution (Overall, 243k CVEs)",
                       "Rule-based labels using description, vendor, and product signals.")

    print(f"\nAll outputs written to {OUTPUT_DIR}/")


def _plot_distribution(counts: Counter, total: int, path: Path,
                       title: str, subtitle: str) -> None:
    rows = [{"IoT_Class": cls,
             "Count": counts.get(cls, 0),
             "Percentage": round(counts.get(cls, 0) / total * 100, 1)}
            for cls in ALL_CLASSES]
    df = pd.DataFrame(rows)

    sns.set_theme(style="whitegrid", context="paper")
    fig, ax = plt.subplots(figsize=(9.5, 5.8), dpi=160)
    fig.patch.set_facecolor("#FBFAF7")
    ax.set_facecolor("#FBFAF7")

    sns.barplot(data=df, x="IoT_Class", y="Count",
                hue="IoT_Class", order=ALL_CLASSES,
                palette=CLASS_PALETTE, dodge=False, legend=False, ax=ax,
                edgecolor="#F7F4ED", linewidth=1.5)

    max_count = float(df["Count"].max()) if len(df) else 1.0
    ax.set_ylim(0, max_count * 1.18)
    ax.grid(axis="y", color="#DDD6C8", linestyle="--", linewidth=0.8, alpha=0.8)
    ax.grid(axis="x", visible=False)
    for spine in ["top", "right", "left"]:
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_color("#C8BEAD")
    ax.set_xlabel("")
    ax.set_ylabel("# Vulnerabilities", fontsize=12, color="#3C3A36")
    ax.set_title(title, fontsize=14, weight="bold", color="#2F2C28", pad=14)
    ax.text(0.0, 1.02, subtitle, transform=ax.transAxes,
            ha="left", va="bottom", fontsize=9, color="#6B655C")

    for patch, row in zip(ax.patches, df.itertuples()):
        h = patch.get_height()
        ax.text(patch.get_x() + patch.get_width() / 2,
                h + max_count * 0.022,
                f"{int(row.Count):,}\n{row.Percentage:.1f}%",
                ha="center", va="bottom", fontsize=8.5,
                color="#2F2C28", weight="semibold")

    plt.tight_layout()
    plt.savefig(path, format="pdf", dpi=300, bbox_inches="tight",
                facecolor=fig.get_facecolor())
    plt.close(fig)
    print(f"  Saved {path}")


if __name__ == "__main__":
    main()
