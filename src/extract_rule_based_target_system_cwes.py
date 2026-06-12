from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


FIVE_CLASSES = ["Home", "SCADA", "Enterprise", "Mobile", "PC"]
ALL_CLASSES = FIVE_CLASSES + ["Other"]
NOTEBOOK_DESCRIPTION_ONLY_COUNTS = {
    "Home": 80,
    "SCADA": 17,
    "Enterprise": 49,
    "Mobile": 24,
    "PC": 206,
    "Other": 516,
}
NOTEBOOK_ENHANCED_COUNTS = {
    "Home": 102,
    "SCADA": 86,
    "Enterprise": 146,
    "Mobile": 38,
    "PC": 208,
    "Other": 312,
}

CLASS_PALETTE = {
    "Home": "#2A9D8F",
    "SCADA": "#C98A00",
    "Enterprise": "#5B6C8F",
    "Mobile": "#D96C54",
    "PC": "#4C78A8",
    "Other": "#A06A3A",
}

PATTERNS = {
    "Home": [
        r"smart\s+(home|thermostat|bulb|lock|speaker|tv|plug|camera|doorbell)",
        r"iot\s+device",
        r"connected\s+device",
        r"home\s+automation",
        r"\b(router|wifi|wireless)\s+(router|access\s+point|device)",
        r"\b(tplink|d-link|asus|netgear|linksys|nest|ring|arlo|wyze|roku)\b",
        r"security\s+camera",
        r"ip\s+camera",
        r"baby\s+monitor",
        r"smart\s+tv",
        r"streaming\s+device",
        r"gaming\s+console",
        r"\b(soho|home\s+router)\b",
        r"home\s+camera",
        r"home\s+security\s+camera",
        r"home\s+surveillance",
        r"yi",
        r"TP-Link ",
    ],
    "SCADA": [
        r"\b(scada|ics|plc|hmi|rtu|dcs)\b",
        r"industrial\s+control",
        r"process\s+control",
        r"supervisory\s+control",
        r"power\s+(grid|plant|station)",
        r"water\s+treatment",
        r"\b(oil|gas)\s+.*\s+(plant|refinery|pipeline)",
        r"medical\s+device",
        r"patient\s+monitor",
        r"hospital\s+equipment",
        r"\b(manufacturing|factory|plant)\b",
        r"\b(automotive|vehicle|car)\b",
        r"engine\s+control",
    ],
    "Enterprise": [
        r"enterprise\s+(network|system|software|application)",
        r"business\s+(network|application)",
        r"corporate\s+(network|environment)",
        r"cloud\s+(service|infrastructure|platform)",
        r"data\s+center",
        r"server\s+(software|application|side|hardware)",
        r"\b(switch|firewall|vpn|load\s+balancer)\b",
        r"\b(cisco|juniper|paloalto|fortinet|vmware|oracle|sap|microsoft\s+server)\b",
        r"storage\s+system",
        r"\b(nas|san)\b",
        r"local area",
        r"Operational Technology",
        r"Information Technology",
    ],
    "Mobile": [
        r"\b(android|ios|iphone|ipad|smartphone|tablet)\b",
        r"mobile\s+(device|phone|application|app|os)",
        r"google\s+play",
        r"app\s+store",
        r"\b(smartwatch|wearable|fitness\s+tracker)\b",
        r"\b(5g|lte|cellular)\b",
    ],
    "PC": [
        r"\b(pc|computer|desktop|laptop|notebook)\b",
        r"personal\s+computer",
        r"\b(windows|linux|macos|ubuntu|debian|centos|red\s+hat)\b",
        r"operating\s+system",
        r"\b(bios|uefi|cpu|gpu|ram|ssd|hard\s+drive|motherboard)\b",
        r"\b(microsoft\s+office|adobe|antivirus|browser)\b",
        r"\b(intel\s+nuc|chrome\s+os)\b",
        r"mac",
    ],
}

VENDOR_CATEGORIES = {
    "Home": [
        "d-link", "tplink", "asus", "netgear", "linksys", "nest", "ring", "arlo",
        "wyze", "roku", "google", "amazon", "apple", "samsung", "xiaomi", "philips",
        "hue", "smartthings", "ecobee", "arlo", "eufy", "blink", "simplisafe",
        "logitech", "harman", "sonos", "bose", "jbl", "belkin", "meross", "tuya",
    ],
    "SCADA": [
        "siemens", "rockwell", "schneider", "abb", "emerson", "honeywell", "yokogawa",
        "mitsubishi", "omron", "fanuc", "beckhoff", "wago", "moxa", "advantech",
        "b&r", "panasonic", "delta", "fujitsu", "hitachi", "toshiba", "general electric",
        "ge", "allen-bradley", "modicon", "telemecanique", "square d", "cutler-hammer",
    ],
    "Enterprise": [
        "cisco", "juniper", "paloalto", "fortinet", "checkpoint", "f5", "arista",
        "extreme", "brocade", "hp", "hewlett-packard", "dell", "ibm", "oracle",
        "sap", "vmware", "red hat", "microsoft", "intel", "amd", "nvidia", "qualcomm",
        "broadcom", "marvell", "micron", "sandisk", "seagate", "western digital",
        "synology", "qnap", "netapp", "emc", "hitachi", "huawei", "zte", "ericsson",
        "nokia", "motorola", "aruba", "ruckus", "ubiquiti",
    ],
    "Mobile": [
        "apple", "samsung", "google", "huawei", "xiaomi", "oppo", "vivo", "oneplus",
        "sony", "lg", "motorola", "nokia", "htc", "blackberry", "asus", "lenovo",
        "zte", "alcatel", "realme", "tecno", "infinix", "fairphone", "nothing",
    ],
    "PC": [
        "dell", "hp", "hewlett-packard", "lenovo", "asus", "acer", "msi", "gigabyte",
        "intel", "amd", "nvidia", "microsoft", "apple", "toshiba", "fujitsu", "samsung",
        "lg", "sony", "panasonic", "sharp", "nec", "epson", "brother", "canon", "ricoh",
        "kyocera", "xerox", "lexmark", "okidata", "konica", "minolta",
    ],
}

PRODUCT_KEYWORDS = {
    "Home": [
        "router", "access point", "mesh", "wifi", "camera", "doorbell", "thermostat",
        "bulb", "light", "plug", "outlet", "switch", "lock", "speaker", "display",
        "hub", "gateway", "bridge", "extender", "repeater", "adapter", "dongle",
    ],
    "SCADA": [
        "plc", "hmi", "rtu", "dcs", "scada", "ics", "controller", "automation",
        "drive", "inverter", "servo", "motor", "sensor", "actuator", "valve",
        "transmitter", "recorder", "logger", "monitor", "panel", "station",
    ],
    "Enterprise": [
        "switch", "firewall", "router", "load balancer", "server", "storage",
        "nas", "san", "array", "appliance", "gateway", "proxy", "vpn", "wireless",
        "controller", "management", "console", "director", "orchestrator", "hypervisor",
    ],
    "Mobile": [
        "phone", "smartphone", "tablet", "pad", "watch", "wearable", "tracker",
        "band", "bracelet", "ring", "glasses", "headset", "earbuds", "charger",
        "battery", "dock", "station", "adapter", "cable",
    ],
    "PC": [
        "laptop", "notebook", "desktop", "pc", "workstation", "server", "all-in-one",
        "mini", "stick", "dongle", "adapter", "card", "motherboard", "cpu", "gpu",
        "ram", "ssd", "hdd", "drive", "monitor", "display", "printer", "scanner",
        "copier", "fax", "projector", "keyboard", "mouse", "webcam", "microphone",
    ],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Reproduce the notebook's rule-based target-system "
            "classification and summarize per-class CVEs and CWE weaknesses."
        )
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("data/both"),
        help="Directory containing CVE JSON files.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("classification"),
        help="Directory where output files will be written.",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=10,
        help="Number of top CWE weaknesses to keep per class.",
    )
    parser.add_argument(
        "--classifier",
        choices=["enhanced", "description-only"],
        default="enhanced",
        help="Rule set to use. 'enhanced' combines description, vendor, and product like the notebook's later cells.",
    )
    return parser.parse_args()


def extract_description(cve_json: dict) -> str:
    try:
        descriptions = cve_json["containers"]["cna"].get("descriptions", [])
        if descriptions:
            return descriptions[0].get("value", "")
    except (KeyError, IndexError, TypeError):
        pass

    try:
        for item in cve_json["containers"].get("adp", []):
            descriptions = item.get("descriptions", [])
            if descriptions:
                return descriptions[0].get("value", "")
    except (KeyError, IndexError, TypeError):
        pass

    return ""


def extract_vendor_product(cve_json: dict) -> tuple[str, str]:
    vendor = "Unknown"
    product = "Unknown"

    try:
        affected = cve_json["containers"]["cna"].get("affected", [])
        if affected:
            vendor = affected[0].get("vendor", vendor)
            product = affected[0].get("product", product)
    except (KeyError, IndexError, TypeError):
        pass

    if vendor != "Unknown":
        return vendor, product

    try:
        for item in cve_json["containers"].get("adp", []):
            affected = item.get("affected", [])
            if affected:
                vendor = affected[0].get("vendor", vendor)
                product = affected[0].get("product", product)
                if vendor != "Unknown":
                    return vendor, product
    except (KeyError, IndexError, TypeError):
        pass

    return vendor, product


def normalize_cwe_id(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    if not value or value.lower() == "n/a":
        return None
    if value.startswith("CWE-"):
        return value
    if value.isdigit():
        return f"CWE-{value}"
    return value


def extract_cwe_details(cve_json: dict) -> dict[str, str]:
    cwe_details: dict[str, str] = {}
    containers = cve_json.get("containers", {})

    problem_type_groups = []
    cna = containers.get("cna", {})
    problem_type_groups.extend(cna.get("problemTypes", []))
    for adp_item in containers.get("adp", []):
        problem_type_groups.extend(adp_item.get("problemTypes", []))

    for problem_type in problem_type_groups:
        for description in problem_type.get("descriptions", []):
            cwe_id = normalize_cwe_id(description.get("cweId"))
            if not cwe_id:
                continue
            cwe_name = (description.get("description") or "").strip()
            if not cwe_name or cwe_name.lower() == "n/a":
                cwe_name = "Unknown weakness name"
            existing = cwe_details.get(cwe_id)
            if existing in (None, "Unknown weakness name"):
                cwe_details[cwe_id] = cwe_name

    return cwe_details


def classify_cve_iot_category(cve_json: dict) -> str:
    description = extract_description(cve_json).lower()
    scores: dict[str, int] = {}

    for category, regex_list in PATTERNS.items():
        score = 0
        for pattern in regex_list:
            matches = re.findall(pattern, description, flags=re.IGNORECASE)
            if matches:
                score += len(matches) * (3 if "\\s" in pattern else 2)
        if score > 0:
            scores[category] = score

    if scores:
        best_category, best_score = max(scores.items(), key=lambda item: item[1])
        if best_score >= 2:
            return best_category

    return "Other"


def enhanced_classify_cve(cve_json: dict) -> str:
    description = extract_description(cve_json).lower()
    vendor, product = extract_vendor_product(cve_json)
    vendor_lower = vendor.lower()
    product_lower = product.lower()
    scores: dict[str, int] = {}

    for category, vendors in VENDOR_CATEGORIES.items():
        for known_vendor in vendors:
            if known_vendor in vendor_lower:
                scores[category] = scores.get(category, 0) + 3

    for category, keywords in PRODUCT_KEYWORDS.items():
        for keyword in keywords:
            if keyword in product_lower:
                scores[category] = scores.get(category, 0) + 2
            if keyword in description:
                scores[category] = scores.get(category, 0) + 1

    rule_label = classify_cve_iot_category(cve_json)
    if rule_label != "Other":
        scores[rule_label] = scores.get(rule_label, 0) + 2

    if scores:
        best_category, best_score = max(scores.items(), key=lambda item: item[1])
        if best_score >= 2:
            return best_category

    return "Other"


def collect_records(
    data_dir: Path,
    classifier_name: str,
) -> tuple[list[dict], Counter, dict[str, Counter], dict[str, dict[str, str]]]:
    records: list[dict] = []
    class_counts: Counter = Counter()
    class_cwe_counts: dict[str, Counter] = {label: Counter() for label in FIVE_CLASSES}
    class_cwe_names: dict[str, dict[str, str]] = {label: {} for label in FIVE_CLASSES}

    classifier = enhanced_classify_cve if classifier_name == "enhanced" else classify_cve_iot_category

    for json_path in sorted(data_dir.rglob("*.json")):
        with json_path.open("r", encoding="utf-8") as handle:
            cve_json = json.load(handle)

        description = extract_description(cve_json)
        if not description.strip():
            continue

        cve_class = classifier(cve_json)
        class_counts[cve_class] += 1

        if cve_class not in FIVE_CLASSES:
            continue

        vendor, product = extract_vendor_product(cve_json)
        cwe_details = extract_cwe_details(cve_json)

        for cwe_id, cwe_name in cwe_details.items():
            class_cwe_counts[cve_class][cwe_id] += 1
            if cwe_id not in class_cwe_names[cve_class] or class_cwe_names[cve_class][cwe_id] == "Unknown weakness name":
                class_cwe_names[cve_class][cwe_id] = cwe_name

        records.append(
            {
                "id": json_path.stem,
                "class": cve_class,
                "vendor": vendor,
                "product": product,
                "description": description,
                "cwe_ids": "; ".join(sorted(cwe_details)),
                "cwe_names": "; ".join(class_cwe_names[cve_class][cwe_id] for cwe_id in sorted(cwe_details)),
            }
        )

    return records, class_counts, class_cwe_counts, class_cwe_names


def write_cve_records(output_path: Path, records: list[dict]) -> None:
    fieldnames = ["id", "class", "vendor", "product", "cwe_ids", "cwe_names", "description"]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for record in sorted(records, key=lambda item: (FIVE_CLASSES.index(item["class"]), item["id"])):
            writer.writerow(record)


def write_cwe_summary(
    output_path: Path,
    class_cwe_counts: dict[str, Counter],
    class_cwe_names: dict[str, dict[str, str]],
    top_n: int,
) -> None:
    fieldnames = ["class", "rank", "cwe_id", "cwe_name", "count"]
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for class_name in FIVE_CLASSES:
            for rank, (cwe_id, count) in enumerate(class_cwe_counts[class_name].most_common(top_n), start=1):
                writer.writerow(
                    {
                        "class": class_name,
                        "rank": rank,
                        "cwe_id": cwe_id,
                        "cwe_name": class_cwe_names[class_name].get(cwe_id, "Unknown weakness name"),
                        "count": count,
                    }
                )


def write_summary_json(
    output_path: Path,
    records: list[dict],
    classifier_name: str,
    class_counts: Counter,
    class_cwe_counts: dict[str, Counter],
    class_cwe_names: dict[str, dict[str, str]],
    top_n: int,
) -> None:
    cve_ids_by_class = {
        class_name: sorted(record["id"] for record in records if record["class"] == class_name)
        for class_name in FIVE_CLASSES
    }

    expected_counts = (
        NOTEBOOK_ENHANCED_COUNTS if classifier_name == "enhanced" else NOTEBOOK_DESCRIPTION_ONLY_COUNTS
    )

    summary = {
        "classifier": classifier_name,
        "class_counts": {label: class_counts.get(label, 0) for label in ALL_CLASSES},
        "expected_notebook_counts": expected_counts,
        "notebook_counts_match": {
            label: class_counts.get(label, 0) == expected
            for label, expected in expected_counts.items()
        },
        "cve_ids_by_class": cve_ids_by_class,
        "top_weaknesses": {},
    }

    for class_name in FIVE_CLASSES:
        summary["top_weaknesses"][class_name] = [
            {
                "cwe_id": cwe_id,
                "cwe_name": class_cwe_names[class_name].get(cwe_id, "Unknown weakness name"),
                "count": count,
            }
            for cwe_id, count in class_cwe_counts[class_name].most_common(top_n)
        ]

    summary["analysis_metrics"] = build_analysis_metrics(class_counts, class_cwe_counts)

    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)


def build_analysis_metrics(class_counts: Counter, class_cwe_counts: dict[str, Counter]) -> dict:
    total_classified = sum(class_counts.get(label, 0) for label in ALL_CLASSES)
    metrics = {
        "distribution": {},
        "cwe_concentration": {},
    }

    for label in ALL_CLASSES:
        count = class_counts.get(label, 0)
        percentage = round((count / total_classified * 100), 2) if total_classified else 0.0
        metrics["distribution"][label] = {"count": count, "percentage": percentage}

    for class_name in FIVE_CLASSES:
        counter = class_cwe_counts[class_name]
        total_observations = sum(counter.values())
        top_items = counter.most_common(3)
        top1 = top_items[0][1] if top_items else 0
        top3 = sum(count for _, count in top_items)
        metrics["cwe_concentration"][class_name] = {
            "unique_cwes": len(counter),
            "total_cwe_observations": total_observations,
            "top1_share_pct": round((top1 / total_observations * 100), 2) if total_observations else 0.0,
            "top3_share_pct": round((top3 / total_observations * 100), 2) if total_observations else 0.0,
        }

    return metrics


def create_distribution_dataframe(class_counts: Counter) -> pd.DataFrame:
    rows = []
    total = sum(class_counts.get(label, 0) for label in ALL_CLASSES)
    for label in ALL_CLASSES:
        count = class_counts.get(label, 0)
        percentage = round((count / total * 100), 1) if total else 0.0
        rows.append({"class": label, "count": count, "percentage": percentage})
    return pd.DataFrame(rows)


def collect_class_counts_only(data_dir: Path, classifier_name: str) -> Counter:
    class_counts: Counter = Counter()
    classifier = enhanced_classify_cve if classifier_name == "enhanced" else classify_cve_iot_category

    for json_path in sorted(data_dir.rglob("*.json")):
        with json_path.open("r", encoding="utf-8") as handle:
            cve_json = json.load(handle)

        description = extract_description(cve_json)
        if not description.strip():
            continue

        class_counts[classifier(cve_json)] += 1

    return class_counts


def write_analysis_report(
    output_path: Path,
    classifier_name: str,
    class_counts: Counter,
    class_cwe_counts: dict[str, Counter],
    class_cwe_names: dict[str, dict[str, str]],
    top_n: int,
) -> None:
    metrics = build_analysis_metrics(class_counts, class_cwe_counts)
    lines = []
    lines.append("# Target-System Weakness Analysis")
    lines.append("")
    lines.append(f"Classifier mode: {classifier_name}")
    lines.append("")
    lines.append("## Class Distribution")
    lines.append("")
    lines.append("| Class | Count | Percentage |")
    lines.append("| --- | ---: | ---: |")
    for label in ALL_CLASSES:
        dist = metrics["distribution"][label]
        lines.append(f"| {label} | {dist['count']} | {dist['percentage']:.2f}% |")

    lines.append("")
    lines.append("## CWE Concentration")
    lines.append("")
    lines.append("| Class | Unique CWEs | Total CWE Observations | Top-1 Share | Top-3 Share |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for class_name in FIVE_CLASSES:
        row = metrics["cwe_concentration"][class_name]
        lines.append(
            f"| {class_name} | {row['unique_cwes']} | {row['total_cwe_observations']} | {row['top1_share_pct']:.2f}% | {row['top3_share_pct']:.2f}% |"
        )

    lines.append("")
    lines.append(f"## Top {top_n} Weaknesses By Class")
    for class_name in FIVE_CLASSES:
        lines.append("")
        lines.append(f"### {class_name}")
        lines.append("")
        lines.append("| Rank | CWE | Name | Count |")
        lines.append("| --- | --- | --- | ---: |")
        for rank, (cwe_id, count) in enumerate(class_cwe_counts[class_name].most_common(top_n), start=1):
            cwe_name = class_cwe_names[class_name].get(cwe_id, "Unknown weakness name")
            safe_name = cwe_name.replace("|", "/")
            lines.append(f"| {rank} | {cwe_id} | {safe_name} | {count} |")

    with output_path.open("w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def draw_distribution_panel(
    ax: plt.Axes,
    class_counts: Counter,
    title: str,
    subtitle: str,
    shared_max_count: int | None = None,
    y_limit: int | None = None,
) -> None:
    plot_df = create_distribution_dataframe(class_counts)
    bars = ax.bar(
        plot_df["class"],
        plot_df["count"],
        color=[CLASS_PALETTE[label] for label in plot_df["class"]],
        edgecolor="#F2EBDD",
        linewidth=1.4,
    )

    panel_max_count = max(plot_df["count"]) if len(plot_df) else 0
    max_count = shared_max_count if shared_max_count is not None else panel_max_count
    upper_limit = y_limit if y_limit is not None else (max_count * 1.38 if max_count else 1)
    ax.set_ylim(0, upper_limit)
    ax.set_title(title, fontsize=18, weight="bold", color="#2F2C28", pad=18)
    if subtitle:
        ax.text(
            0.0,
            1.01,
            subtitle,
            transform=ax.transAxes,
            ha="left",
            va="bottom",
            fontsize=10,
            color="#6B655C",
        )
    ax.set_xlabel("")
    ax.set_ylabel("# Vulnerabilities", fontsize=12, color="#3C3A36")
    ax.tick_params(axis="x", labelsize=13, colors="#3C3A36")
    ax.tick_params(axis="y", labelsize=10, colors="#6B655C")
    ax.grid(axis="y", color="#DDD6C8", linestyle="--", linewidth=0.8, alpha=0.8)
    ax.grid(axis="x", visible=False)
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.spines["bottom"].set_color("#C8BEAD")
    ax.margins(y=0.08)

    label_offset = max(panel_max_count * 0.018, 1)
    label_ceiling = upper_limit * 0.93
    for bar, (_, row) in zip(bars, plot_df.iterrows()):
        label_y = bar.get_height() + label_offset
        va = "bottom"
        if label_y > label_ceiling:
            label_y = label_ceiling
            va = "top"
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            label_y,
            f"{row['count']}\n{row['percentage']:.1f}%",
            ha="center",
            va=va,
            fontsize=10,
            color="#2F2C28",
            weight="semibold",
            clip_on=True,
        )


def plot_class_distribution(output_path: Path, class_counts: Counter, classifier_name: str) -> None:
    sns.set_theme(style="whitegrid", context="talk")
    title = "Description-Only Target-System Distribution" if classifier_name == "description-only" else "Enhanced Target-System Distribution"
    subtitle = (
        "Rule-based labels from description text only."
        if classifier_name == "description-only"
        else "Rule-based labels using description, vendor, and product signals."
    )

    fig, ax = plt.subplots(figsize=(10.5, 6.2), dpi=180)
    fig.patch.set_facecolor("#FBFAF7")
    ax.set_facecolor("#FBFAF7")
    draw_distribution_panel(ax, class_counts, title, subtitle)
    plt.tight_layout()
    plt.savefig(output_path, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


def plot_distribution_comparison(
    output_path: Path,
    description_counts: Counter,
    enhanced_counts: Counter,
) -> None:
    sns.set_theme(style="whitegrid", context="talk")
    fig, axes = plt.subplots(1, 2, figsize=(16, 6.2), dpi=180, sharey=True)
    fig.patch.set_facecolor("#FBFAF7")
    for ax in axes:
        ax.set_facecolor("#FBFAF7")

    shared_max_count = max(
        max(description_counts.get(label, 0) for label in ALL_CLASSES),
        max(enhanced_counts.get(label, 0) for label in ALL_CLASSES),
    )
    comparison_y_limit = 600

    draw_distribution_panel(
        axes[0],
        description_counts,
        "Description-Only Rules",
        "",
        shared_max_count=shared_max_count,
        y_limit=comparison_y_limit,
    )
    draw_distribution_panel(
        axes[1],
        enhanced_counts,
        "Description + Vendor + Product",
        "",
        shared_max_count=shared_max_count,
        y_limit=comparison_y_limit,
    )
    axes[1].set_ylabel("")
    plt.tight_layout()
    plt.savefig(output_path, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)


def plot_cwe_heatmap(
    output_path: Path,
    class_cwe_counts: dict[str, Counter],
    class_cwe_names: dict[str, dict[str, str]],
    top_n: int,
) -> None:
    selected_cwes = []
    for class_name in FIVE_CLASSES:
        selected_cwes.extend(cwe_id for cwe_id, _ in class_cwe_counts[class_name].most_common(top_n))

    ordered_cwes = []
    for cwe_id in selected_cwes:
        if cwe_id not in ordered_cwes:
            ordered_cwes.append(cwe_id)

    if not ordered_cwes:
        return

    data = []
    for cwe_id in ordered_cwes:
        row = {"cwe": cwe_id}
        total = 0
        for class_name in FIVE_CLASSES:
            value = class_cwe_counts[class_name].get(cwe_id, 0)
            row[class_name] = value
            total += value
        row["_total"] = total
        data.append(row)

    heatmap_df = pd.DataFrame(data).sort_values("_total", ascending=False).head(top_n).drop(columns=["_total"])
    heatmap_df = heatmap_df.set_index("cwe")

    sns.set_theme(style="white", context="paper", font_scale=2.0)
    fig_height = max(6, 0.35 * len(heatmap_df) + 2)
    fig, ax = plt.subplots(figsize=(9, fig_height), dpi=180)
    sns.heatmap(
        heatmap_df,
        annot=True,
        fmt="d",
        cmap="YlGnBu",
        linewidths=0.5,
        cbar_kws={"label": "CWE count"},
        annot_kws={"size": 14},
        ax=ax,
    )

    #.ax.set_title(f"Top {top_n} CWE Overlap Across Target-System Classes", fontsize=16, weight="bold", pad=14)
    ax.set_xlabel("")
    ax.set_ylabel("")
    for label in ax.get_yticklabels():
        label.set_ha("left")
    ax.yaxis.set_tick_params(pad=90)
    plt.tight_layout()
    plt.savefig(output_path, bbox_inches="tight")
    plt.close(fig)


def plot_top_overlap_heatmap(
    output_path: Path,
    class_cwe_counts: dict[str, Counter],
    top_k: int,
) -> None:
    overlap_rows = []
    for cwe_id in sorted({cwe_id for counter in class_cwe_counts.values() for cwe_id in counter}):
        row = {"cwe": cwe_id}
        class_presence = 0
        total = 0
        for class_name in FIVE_CLASSES:
            value = class_cwe_counts[class_name].get(cwe_id, 0)
            row[class_name] = value
            total += value
            if value > 0:
                class_presence += 1

        if class_presence < 2:
            continue

        row["_class_presence"] = class_presence
        row["_total"] = total
        overlap_rows.append(row)

    if not overlap_rows:
        return

    heatmap_df = pd.DataFrame(overlap_rows).sort_values(
        ["_class_presence", "_total", "cwe"],
        ascending=[False, False, True],
    ).head(top_k)
    heatmap_df = heatmap_df[["cwe", *FIVE_CLASSES]].set_index("cwe")

    sns.set_theme(style="white", context="paper")
    fig_height = max(6, 0.38 * len(heatmap_df) + 2)
    fig, ax = plt.subplots(figsize=(9.5, fig_height), dpi=180)
    sns.heatmap(
        heatmap_df,
        annot=True,
        fmt="d",
        cmap="YlOrBr",
        linewidths=0.5,
        cbar_kws={"label": "CWE count"},
        ax=ax,
    )

    ax.set_title(
        "Top 20 CWE Overlap Across Classes\nEnhanced Rules: Description + Vendor + Product",
        fontsize=16,
        weight="bold",
        pad=14,
    )
    ax.set_xlabel("")
    ax.set_ylabel("CWE")
    plt.tight_layout()
    plt.savefig(output_path, bbox_inches="tight")
    plt.close(fig)


def plot_cwe_concentration(output_path: Path, class_cwe_counts: dict[str, Counter]) -> None:
    metrics = []
    for class_name in FIVE_CLASSES:
        counter = class_cwe_counts[class_name]
        total = sum(counter.values())
        top1 = counter.most_common(1)[0][1] if counter else 0
        top3 = sum(count for _, count in counter.most_common(3))
        metrics.append(
            {
                "class": class_name,
                "Top-1 Share": (top1 / total * 100) if total else 0.0,
                "Top-3 Share": (top3 / total * 100) if total else 0.0,
            }
        )

    plot_df = pd.DataFrame(metrics).melt(id_vars="class", var_name="metric", value_name="percentage")

    sns.set_theme(style="whitegrid", context="talk")
    fig, ax = plt.subplots(figsize=(10, 6), dpi=180)
    sns.barplot(data=plot_df, x="class", y="percentage", hue="metric", palette=["#4C78A8", "#F58518"], ax=ax)
    ax.set_title("CWE Concentration By Class", fontsize=18, weight="bold")
    ax.set_xlabel("")
    ax.set_ylabel("Share of CWE observations (%)")
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(title="")

    for container in ax.containers:
        ax.bar_label(container, fmt="%.1f", padding=3, fontsize=9)

    plt.tight_layout()
    plt.savefig(output_path, bbox_inches="tight")
    plt.close(fig)


def write_analysis_artifacts(
    output_dir: Path,
    classifier_name: str,
    description_counts: Counter,
    enhanced_counts: Counter,
    class_counts: Counter,
    class_cwe_counts: dict[str, Counter],
    class_cwe_names: dict[str, dict[str, str]],
    enhanced_class_cwe_counts: dict[str, Counter],
    top_n: int,
) -> list[Path]:
    output_paths = []
    distribution_plot = output_dir / "five-target-system-distribution.pdf"
    description_distribution_plot = output_dir / "five-target-system-description-only-distribution.pdf"
    enhanced_distribution_plot = output_dir / "five-target-system-enhanced-distribution.pdf"
    comparison_plot = output_dir / "five-target-system-distribution-comparison.pdf"
    heatmap_plot = output_dir / "five-target-system-cwe-heatmap.pdf"
    enhanced_overlap_heatmap_plot = output_dir / "five-target-system-cwe-heatmap-enhanced-top20-overlap.pdf"
    concentration_plot = output_dir / "five-target-system-cwe-concentration.pdf"
    report_path = output_dir / "five-target-system-analysis.md"

    plot_class_distribution(distribution_plot, class_counts, classifier_name)
    plot_class_distribution(description_distribution_plot, description_counts, "description-only")
    plot_class_distribution(enhanced_distribution_plot, enhanced_counts, "enhanced")
    plot_distribution_comparison(comparison_plot, description_counts, enhanced_counts)
    plot_cwe_heatmap(heatmap_plot, class_cwe_counts, class_cwe_names, top_n)
    plot_top_overlap_heatmap(enhanced_overlap_heatmap_plot, enhanced_class_cwe_counts, top_k=20)
    plot_cwe_concentration(concentration_plot, class_cwe_counts)
    write_analysis_report(report_path, classifier_name, class_counts, class_cwe_counts, class_cwe_names, top_n)

    output_paths.extend(
        [
            distribution_plot,
            description_distribution_plot,
            enhanced_distribution_plot,
            comparison_plot,
            heatmap_plot,
            enhanced_overlap_heatmap_plot,
            concentration_plot,
            report_path,
        ]
    )
    return output_paths


def print_summary(
    classifier_name: str,
    class_counts: Counter,
    class_cwe_counts: dict[str, Counter],
    class_cwe_names: dict[str, dict[str, str]],
    top_n: int,
) -> None:
    expected_counts = (
        NOTEBOOK_ENHANCED_COUNTS if classifier_name == "enhanced" else NOTEBOOK_DESCRIPTION_ONLY_COUNTS
    )
    heading = "Enhanced rule-based counts" if classifier_name == "enhanced" else "Description-only rule-based counts"
    print(f"{heading}:")
    for label in ALL_CLASSES:
        actual = class_counts.get(label, 0)
        expected = expected_counts.get(label)
        marker = "OK" if expected == actual else "MISMATCH"
        print(f"  {label:10s} {actual:4d}  expected={expected:4d}  {marker}")

    print("\nTop weaknesses per explicit target-system class:")
    for class_name in FIVE_CLASSES:
        print(f"\n[{class_name}] {class_counts.get(class_name, 0)} CVEs")
        if not class_cwe_counts[class_name]:
            print("  No CWE IDs found for this class.")
            continue
        for cwe_id, count in class_cwe_counts[class_name].most_common(top_n):
            cwe_name = class_cwe_names[class_name].get(cwe_id, "Unknown weakness name")
            print(f"  {cwe_id:12s} {count:3d}  {cwe_name}")


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    description_counts = collect_class_counts_only(args.data_dir, "description-only")
    enhanced_counts = collect_class_counts_only(args.data_dir, "enhanced")
    _, _, enhanced_class_cwe_counts, _ = collect_records(args.data_dir, "enhanced")
    records, class_counts, class_cwe_counts, class_cwe_names = collect_records(args.data_dir, args.classifier)

    cve_output = args.output_dir / "five-target-system-cves.csv"
    cwe_output = args.output_dir / "five-target-system-top-weaknesses.csv"
    summary_output = args.output_dir / "five-target-system-summary.json"

    write_cve_records(cve_output, records)
    write_cwe_summary(cwe_output, class_cwe_counts, class_cwe_names, args.top_n)
    write_summary_json(
        summary_output,
        records,
        args.classifier,
        class_counts,
        class_cwe_counts,
        class_cwe_names,
        args.top_n,
    )
    analysis_outputs = write_analysis_artifacts(
        args.output_dir,
        args.classifier,
        description_counts,
        enhanced_counts,
        class_counts,
        class_cwe_counts,
        class_cwe_names,
        enhanced_class_cwe_counts,
        args.top_n,
    )

    print_summary(args.classifier, class_counts, class_cwe_counts, class_cwe_names, args.top_n)
    print(f"\nWrote {len(records)} explicit-class CVE records to {cve_output}")
    print(f"Wrote CWE summary to {cwe_output}")
    print(f"Wrote JSON summary to {summary_output}")
    for output_path in analysis_outputs:
        print(f"Wrote analysis artifact to {output_path}")


if __name__ == "__main__":
    main()