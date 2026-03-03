# UpdatOR

Understanding Security Failures in Update Mechanisms: an empirical analysis of software and firmware update-related vulnerabilities.

This repository contains the dataset slices, scripts, notebooks, and analysis artifacts used in the UpdatOR study for vulnerabilities disclosed from 2016 to 2025.

Paper (local copy): `doc/Ahmad_COSE_Journal-2.pdf`

## Overview

UpdatOR studies update-related vulnerabilities (software and firmware) against the broader vulnerability population.

The analysis in this repository covers:

- **RQ1**: How update-related vulnerabilities differ from overall vulnerabilities in exploitability, impact, and severity.
- **RQ2**: The most common update-related weaknesses (CWE) and their patterns.
- **RQ3**: Target-system classification (`Home`, `SCADA`, `Enterprise`, `Mobile`, `PC`, `Other`) using rule-based + SVM methods.

The paper also includes mitigation recommendations and a recommendation matrix (RQ4).

## Repository layout

Main folders:

- `doc/` – paper PDF used for the study documentation.
- `cvelistV5/` – snapshot/local copy of CVE List V5 records (2016–2025 folders under `cves/`).
- `data/` – curated JSON datasets:
	- `data/overall/` – broad vulnerability population.
	- `data/both/` – update-related vulnerability subset.
	- `data_fw/`, `data_sw/` – firmware/software focused subsets.
- `src/` – analysis scripts and notebooks.
- `classification_both/`, `classification_overall/` – classified CVE outputs (`target-system.csv`) and related figures.
- `cvss_plots_*`, `cwe_plots_*` – generated visualization outputs.
- `svm/`, `svm_both/`, `svm_overall/` – SVM artifacts and experiment outputs.

## Environment setup

### 1) Create and activate virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 2) Install dependencies

```bash
pip install -r requirements.txt
```

`requirements.txt` includes core libraries used across scripts and notebooks (e.g., `pandas`, `matplotlib`, `seaborn`, `scikit-learn`, `torch`, `transformers`).

## Reproducibility guide

Most scripts are intended to be run from the repository root.

### A) CWE analysis (RQ2)

Script: `src/cwe_stats.py`

What it does:
- Recursively scans a selected dataset folder for CVE JSON files.
- Extracts CWE IDs from both `containers.cna` and `containers.adp`.
- Produces summary statistics, frequency tables, and PDF plots.
- Saves CSV outputs (`cwe_frequency.csv`, `cwe_locations.csv`).

Run:

```bash
python src/cwe_stats.py
```

Before running, set `dataset_folder` in the script (examples are already included):
- `./data/overall`
- `./data/both`
- `./data/data_fw`
- `./data/data_sw`

### B) CVSS metric extraction and severity profiling (RQ1)

Primary script: `src/cvss_metrics.py`

What it does:
- Extracts CVSS v3/v2 metrics from nested CVE JSON records.
- Computes metric frequencies and severity levels.
- Supports analysis across CNA and ADP containers.

Run:

```bash
python src/cvss_metrics.py
```

Related plotting/summary scripts:
- `src/cvss_metric_plot.py`
- `src/severity.py`
- `src/scattered_boxplot.py`
- `src/violin_plot_h.py`, `src/violin_plot_v.py`

### C) Target-system classification (RQ3)

Data outputs:
- `classification_both/target-system.csv`
- `classification_overall/target-system.csv`

Approach in repository:
- Rule-based labeling with description/vendor/product cues.
- SVM-based modeling and evaluation (`src/classification_SVM.ipynb`, `svm*` folders).

Notebooks/scripts to inspect:
- `src/classification_rule_based.ipynb`
- `src/classification_SVM.ipynb`
- `src/classification.ipynb`

## Notes on data and format

- CVE JSON files follow CVE Record Format v5.x, and records can contain multiple containers (`cna`, optional `adp`), which is handled by key scripts.
- `cvelistV5/README.md` contains upstream CVE list format notes and update-policy details.

## Current status

This repository already includes generated artifacts (plots/classification CSVs), scripts, and notebooks used during the study.

If you want a strict one-command pipeline for full end-to-end regeneration (all RQ outputs), the next step is to add a unified runner script (e.g., `Makefile` or `python -m` pipeline) that orchestrates all stages.

