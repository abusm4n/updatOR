import os
import json
from collections import Counter

def find_json_files(root_folder):
    """Find all JSON files in nested folders recursively"""
    json_files = []
    for root, dirs, files in os.walk(root_folder):
        for file in files:
            if file.endswith('.json'):
                json_files.append(os.path.join(root, file))
    return json_files

def extract_metrics(cvss_data):
    """Extract CVSS metrics from CVSS data object"""
    metrics = {}
    
    if 'cvssV3_1' in cvss_data:
        cvss = cvss_data['cvssV3_1']
        # Try to get from vectorString first, then from direct fields
        vector_string = cvss.get('vectorString', '')
        if vector_string:
            metrics = parse_vector_string(vector_string)
        else:
            # Extract from individual fields if vectorString is not available
            metrics = {
                'Confidentiality': cvss.get('confidentialityImpact', 'N/A'),
                'Integrity': cvss.get('integrityImpact', 'N/A'),
                'Availability': cvss.get('availabilityImpact', 'N/A'),
                'Attack Vector': cvss.get('attackVector', 'N/A'),
                'Attack Complexity': cvss.get('attackComplexity', 'N/A'),
                'Privileges Required': cvss.get('privilegesRequired', 'N/A'),
                'User Interaction': cvss.get('userInteraction', 'N/A'),
                'Scope': cvss.get('scope', 'N/A'),
                'baseSeverity': cvss.get('baseSeverity', 'N/A')
            }
        
    elif 'cvssV3_0' in cvss_data:
        cvss = cvss_data['cvssV3_0']
        vector_string = cvss.get('vectorString', '')
        if vector_string:
            metrics = parse_vector_string(vector_string)
        else:
            metrics = {
                'Confidentiality': cvss.get('confidentialityImpact', 'N/A'),
                'Integrity': cvss.get('integrityImpact', 'N/A'),
                'Availability': cvss.get('availabilityImpact', 'N/A'),
                'Attack Vector': cvss.get('attackVector', 'N/A'),
                'Attack Complexity': cvss.get('attackComplexity', 'N/A'),
                'Privileges Required': cvss.get('privilegesRequired', 'N/A'),
                'User Interaction': cvss.get('userInteraction', 'N/A'),
                'Scope': cvss.get('scope', 'N/A'),
                'baseSeverity': cvss.get('baseSeverity', 'N/A')
            }

    elif 'cvssV2_0' in cvss_data:
        cvss = cvss_data['cvssV2_0']
        vector_string = cvss.get('vectorString', '')
        if vector_string:
            metrics = parse_vector_string_v2(vector_string)
        else:
            metrics = {
                'Confidentiality': cvss.get('confidentialityImpact', 'N/A'),
                'Integrity': cvss.get('integrityImpact', 'N/A'),
                'Availability': cvss.get('availabilityImpact', 'N/A'),
                'Attack Vector': cvss.get('accessVector', 'N/A'),
                'Attack Complexity': cvss.get('accessComplexity', 'N/A'),
                'Authentication': cvss.get('authentication', 'N/A'),
                'baseSeverity': 'N/A'  # Will be calculated from baseScore
            }
    
    return metrics

def parse_vector_string(vector_string):
    """Parse CVSS v3.x vector string"""
    metrics = {
        'Confidentiality': 'N/A',
        'Integrity': 'N/A',
        'Availability': 'N/A',
        'Attack Vector': 'N/A',
        'Attack Complexity': 'N/A',
        'Privileges Required': 'N/A',
        'User Interaction': 'N/A',
        'Scope': 'N/A',
        'baseSeverity': 'N/A'
    }

    if not vector_string:
        return metrics
    
    vector_parts = vector_string.split('/')
    for part in vector_parts:
        if ':' in part:
            key, value = part.split(':')
            if key == 'C':
                metrics['Confidentiality'] = value
            elif key == 'I':
                metrics['Integrity'] = value
            elif key == 'A':
                metrics['Availability'] = value
            elif key == 'AV':
                metrics['Attack Vector'] = value
            elif key == 'AC':
                metrics['Attack Complexity'] = value
            elif key == 'PR':
                metrics['Privileges Required'] = value
            elif key == 'UI':
                metrics['User Interaction'] = value
            elif key == 'S':
                metrics['Scope'] = value
    
    return metrics

def parse_vector_string_v2(vector_string):
    """Parse CVSS v2.0 vector string"""
    metrics = {
        'Confidentiality': 'N/A',
        'Integrity': 'N/A',
        'Availability': 'N/A',
        'Attack Vector': 'N/A',
        'Attack Complexity': 'N/A',
        'Authentication': 'N/A',
        'baseSeverity': 'N/A'
    }

    if not vector_string:
        return metrics
    
    vector_parts = vector_string.split('/')
    for part in vector_parts:
        if ':' in part:
            key, value = part.split(':')
            if key == 'C':
                metrics['Confidentiality'] = value
            elif key == 'I':
                metrics['Integrity'] = value
            elif key == 'A':
                metrics['Availability'] = value
            elif key == 'AV':
                metrics['Attack Vector'] = value
            elif key == 'AC':
                metrics['Attack Complexity'] = value
            elif key == 'Au':
                metrics['Authentication'] = value
    
    return metrics

def extract_severity_from_cvss(cvss_data):
    """Extract severity level from CVSS data object"""
    severity = 'N/A'
    
    if 'cvssV3_1' in cvss_data:
        cvss = cvss_data['cvssV3_1']
        # First try to get baseSeverity directly
        base_severity = cvss.get('baseSeverity')
        if base_severity:
            # Map to standard severity levels
            if base_severity == 'CRITICAL':
                severity = 'Critical'
            elif base_severity == 'HIGH':
                severity = 'High'
            elif base_severity == 'MEDIUM':
                severity = 'Medium'
            elif base_severity == 'LOW':
                severity = 'Low'
        else:
            # Calculate from baseScore if baseSeverity is not available
            base_score = cvss.get('baseScore')
            if base_score is not None:
                severity = calculate_severity_from_score(base_score, 'v3')
        
    elif 'cvssV3_0' in cvss_data:
        cvss = cvss_data['cvssV3_0']
        base_severity = cvss.get('baseSeverity')
        if base_severity:
            if base_severity == 'CRITICAL':
                severity = 'Critical'
            elif base_severity == 'HIGH':
                severity = 'High'
            elif base_severity == 'MEDIUM':
                severity = 'Medium'
            elif base_severity == 'LOW':
                severity = 'Low'
        else:
            base_score = cvss.get('baseScore')
            if base_score is not None:
                severity = calculate_severity_from_score(base_score, 'v3')
                
    elif 'cvssV2_0' in cvss_data:
        cvss = cvss_data['cvssV2_0']
        base_score = cvss.get('baseScore')
        if base_score is not None:
            severity = calculate_severity_from_score(base_score, 'v2')
    
    return severity

def calculate_severity_from_score(base_score, cvss_version):
    """Calculate severity level from base score"""
    if cvss_version == 'v3':
        if base_score >= 9.0:
            return 'Critical'
        elif base_score >= 7.0:
            return 'High'
        elif base_score >= 4.0:
            return 'Medium'
        elif base_score >= 0.1:
            return 'Low'
        else:
            return 'N/A'
    else:  # CVSS v2
        if base_score >= 7.0:
            return 'High'
        elif base_score >= 4.0:
            return 'Medium'
        elif base_score >= 0.1:
            return 'Low'
        else:
            return 'N/A'

def process_json_files(folder_path):
    """Process all JSON files in the folder and subfolders recursively"""
    # Initialize counters for metrics frequency
    frequency_counter = {
        'Confidentiality': Counter(),
        'Integrity': Counter(),
        'Availability': Counter(),
        'Attack Vector': Counter(),
        'Attack Complexity': Counter(),
        'Privileges Required': Counter(),
        'User Interaction': Counter(),
        'Scope': Counter(),
        'baseSeverity': Counter(),
        'SeverityLevel': Counter()  # New counter for severity level
    }
    
    # Additional counters for CVSS v2
    frequency_counter_v2 = {
        'Authentication': Counter()
    }
    
    total_files = 0
    files_with_metrics = 0
    files_processed = 0
    cvss_v2_files = 0
    cvss_v3_files = 0
    
    # Find all JSON files in nested folders
    print(f"Searching for JSON files in '{folder_path}' and subdirectories...")
    json_file_paths = find_json_files(folder_path)
    print(f"Found {len(json_file_paths)} JSON files to process")
    
    # Iterate over all JSON files in the dataset folder and subfolders
    for file_path in json_file_paths:
        total_files += 1  # Count the total number of files
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            has_metrics = False
            cvss_version = None
            
            # First check for metrics in cna (CVE 5.0 format)
            cna_metrics = data.get('containers', {}).get('cna', {}).get('metrics', [])
            if cna_metrics:
                has_metrics = True
                for cvss_data in cna_metrics:
                    metrics = extract_metrics(cvss_data)
                    if metrics:
                        # Extract severity level
                        severity_level = extract_severity_from_cvss(cvss_data)
                        if severity_level != 'N/A':
                            frequency_counter['SeverityLevel'][severity_level] += 1
                        
                        # Check CVSS version
                        if 'cvssV2_0' in cvss_data:
                            cvss_version = "v2.0"
                            cvss_v2_files += 1
                            # Add v2 specific metrics
                            if 'Authentication' in metrics:
                                frequency_counter_v2['Authentication'][metrics['Authentication']] += 1
                        elif 'cvssV3_0' in cvss_data or 'cvssV3_1' in cvss_data:
                            cvss_version = "v3.x"
                            cvss_v3_files += 1
                        
                        # Update the frequency counters
                        for key, value in metrics.items():
                            if key in frequency_counter:
                                frequency_counter[key][value] += 1
            
            # Then check for metrics in adp (if not found in cna)
            if not has_metrics:
                adp_list = data.get('containers', {}).get('adp', [])
                for adp in adp_list:
                    adp_metrics = adp.get('metrics', [])
                    if adp_metrics:
                        has_metrics = True
                        for cvss_data in adp_metrics:
                            metrics = extract_metrics(cvss_data)
                            if metrics:
                                # Extract severity level
                                severity_level = extract_severity_from_cvss(cvss_data)
                                if severity_level != 'N/A':
                                    frequency_counter['SeverityLevel'][severity_level] += 1
                                
                                # Check CVSS version
                                if 'cvssV2_0' in cvss_data:
                                    cvss_version = "v2.0"
                                    cvss_v2_files += 1
                                    # Add v2 specific metrics
                                    if 'Authentication' in metrics:
                                        frequency_counter_v2['Authentication'][metrics['Authentication']] += 1
                                elif 'cvssV3_0' in cvss_data or 'cvssV3_1' in cvss_data:
                                    cvss_version = "v3.x"
                                    cvss_v3_files += 1
                                
                                # Update the frequency counters
                                for key, value in metrics.items():
                                    if key in frequency_counter:
                                        frequency_counter[key][value] += 1
            
            # If no CVE 5.0 format metrics found, try legacy format
            if not has_metrics:
                # Try legacy format (CVE 4.x)
                impact_data = data.get('impact', {})
                if isinstance(impact_data, dict):
                    # Check for CVSS v3
                    cvss_v3 = impact_data.get('baseMetricV3', {}).get('cvssV3', {})
                    if cvss_v3:
                        has_metrics = True
                        cvss_version = "v3.x"
                        cvss_v3_files += 1
                        
                        # Extract metrics from legacy format
                        base_score = cvss_v3.get('baseScore')
                        if base_score is not None:
                            severity = calculate_severity_from_score(base_score, 'v3')
                            frequency_counter['SeverityLevel'][severity] += 1
                            
                            # Add to baseSeverity counter as well
                            if severity == 'Critical':
                                frequency_counter['baseSeverity']['CRITICAL'] += 1
                            elif severity == 'High':
                                frequency_counter['baseSeverity']['HIGH'] += 1
                            elif severity == 'Medium':
                                frequency_counter['baseSeverity']['MEDIUM'] += 1
                            elif severity == 'Low':
                                frequency_counter['baseSeverity']['LOW'] += 1
                    
                    # Check for CVSS v2 if v3 not found
                    elif not cvss_v3:
                        cvss_v2 = impact_data.get('baseMetricV2', {}).get('cvssV2', {})
                        if cvss_v2:
                            has_metrics = True
                            cvss_version = "v2.0"
                            cvss_v2_files += 1
                            
                            # Extract metrics from legacy format
                            base_score = cvss_v2.get('baseScore')
                            if base_score is not None:
                                severity = calculate_severity_from_score(base_score, 'v2')
                                frequency_counter['SeverityLevel'][severity] += 1
                                
                                # Add to baseSeverity counter as well
                                if severity == 'High':
                                    frequency_counter['baseSeverity']['HIGH'] += 1
                                elif severity == 'Medium':
                                    frequency_counter['baseSeverity']['MEDIUM'] += 1
                                elif severity == 'Low':
                                    frequency_counter['baseSeverity']['LOW'] += 1
            
            if has_metrics:
                files_with_metrics += 1
            
            files_processed += 1
            
            # Show progress
            if files_processed % 100 == 0:
                print(f"  Processed {files_processed} files...")
                
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")
    
    # Merge v2 specific metrics into main counter
    if frequency_counter_v2['Authentication']:
        frequency_counter['Authentication'] = frequency_counter_v2['Authentication']
    
    return frequency_counter, total_files, files_with_metrics, files_processed, cvss_v2_files, cvss_v3_files

def print_frequencies_with_percentages(frequency_counter, metric_type="All Metrics"):
    """Print frequency counts with percentages"""
    print(f"\n{'='*60}")
    print(f"{metric_type} DISTRIBUTION WITH PERCENTAGES")
    print(f"{'='*60}")
    
    for metric, counts in frequency_counter.items():
        total_count = sum(counts.values())
        if total_count == 0:
            continue
            
        print(f"\n{metric}:")
        print("-" * 40)
        
        # Sort by count descending, then alphabetically
        sorted_counts = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
        
        for value, count in sorted_counts:
            percentage = (count / total_count) * 100
            print(f"  {value}: {count} ({percentage:.1f}%)")
        
        print(f"  Total entries: {total_count}")

# Folder containing the dataset
dataset_folder = './data/both'

# Process the JSON files and get the frequency counts
print("="*60)
print("CVSS METRICS ANALYSIS SUMMARY")
print("="*60)

frequency_counts, total_files, files_with_metrics, files_processed, cvss_v2_files, cvss_v3_files = process_json_files(dataset_folder)

# Print processing summary
print(f"\nProcessing Summary:")
print(f"Total JSON files found: {total_files}")
print(f"Files successfully processed: {files_processed}")
print(f"Files containing CVSS metrics: {files_with_metrics}")
print(f"Files with CVSS v2.0 metrics: {cvss_v2_files}")
print(f"Files with CVSS v3.x metrics: {cvss_v3_files}")

# Print all metrics with percentages
print_frequencies_with_percentages(frequency_counts, "ALL METRICS")

# Specialized breakdowns
print("\n" + "="*60)
print("CIA TRIAD IMPACT LEVELS (Confidentiality, Integrity, Availability)")
print("="*60)

cia_metrics = ['Confidentiality', 'Integrity', 'Availability']
for metric in cia_metrics:
    if metric in frequency_counts and frequency_counts[metric]:
        counts = frequency_counts[metric]
        total = sum(counts.values())
        
        print(f"\n{metric}:")
        # Group by HIGH, MEDIUM, LOW, NONE, N/A
        levels = ['HIGH', 'MEDIUM', 'LOW', 'NONE', 'N/A']
        for level in levels:
            count = counts.get(level, 0)
            if count > 0:
                percentage = (count / total) * 100
                print(f"  {level}: {count} ({percentage:.1f}%)")

# Attack Vector breakdown
print("\n" + "="*60)
print("ATTACK VECTOR DISTRIBUTION")
print("="*60)
if 'Attack Vector' in frequency_counts and frequency_counts['Attack Vector']:
    av_counts = frequency_counts['Attack Vector']
    total_av = sum(av_counts.values())
    
    # Map CVSS abbreviations to readable names
    av_mapping = {
        'N': 'NETWORK',
        'A': 'ADJACENT_NETWORK',
        'L': 'LOCAL',
        'P': 'PHYSICAL'
    }
    
    print("\nAttack Vector Breakdown:")
    for abbr, readable in av_mapping.items():
        count = av_counts.get(abbr, 0) + av_counts.get(readable, 0)
        if count > 0:
            percentage = (count / total_av) * 100
            print(f"  {readable}: {count} ({percentage:.1f}%)")
    
    # Handle any other values
    for value, count in av_counts.items():
        if value not in av_mapping and value not in av_mapping.values():
            if count > 0:
                percentage = (count / total_av) * 100
                print(f"  {value}: {count} ({percentage:.1f}%)")

# Severity Level breakdown (NEW)
print("\n" + "="*60)
print("SEVERITY LEVEL DISTRIBUTION (Critical/High/Medium/Low)")
print("="*60)
if 'SeverityLevel' in frequency_counts and frequency_counts['SeverityLevel']:
    severity_counts = frequency_counts['SeverityLevel']
    total_severity = sum(severity_counts.values())
    
    print("\nSeverity Levels:")
    severity_levels = ['Critical', 'High', 'Medium', 'Low', 'N/A']
    for severity in severity_levels:
        count = severity_counts.get(severity, 0)
        if count > 0:
            percentage = (count / total_severity) * 100
            print(f"  {severity}: {count} ({percentage:.1f}%)")

# Base Severity breakdown (from CVSS field)
print("\n" + "="*60)
print("BASE SEVERITY DISTRIBUTION (from CVSS baseSeverity field)")
print("="*60)
if 'baseSeverity' in frequency_counts and frequency_counts['baseSeverity']:
    base_severity_counts = frequency_counts['baseSeverity']
    total_base_severity = sum(base_severity_counts.values())
    
    print("\nBase Severity Levels:")
    base_severity_levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'N/A']
    for severity in base_severity_levels:
        count = base_severity_counts.get(severity, 0)
        if count > 0:
            percentage = (count / total_base_severity) * 100
            print(f"  {severity}: {count} ({percentage:.1f}%)")

# Attack Complexity breakdown
print("\n" + "="*60)
print("ATTACK COMPLEXITY DISTRIBUTION")
print("="*60)
if 'Attack Complexity' in frequency_counts and frequency_counts['Attack Complexity']:
    ac_counts = frequency_counts['Attack Complexity']
    total_ac = sum(ac_counts.values())
    
    print("\nAttack Complexity Levels:")
    ac_levels = ['LOW', 'HIGH', 'N/A']
    for level in ac_levels:
        count = ac_counts.get(level, 0)
        if count > 0:
            percentage = (count / total_ac) * 100
            print(f"  {level}: {count} ({percentage:.1f}%)")

# User Interaction breakdown
print("\n" + "="*60)
print("USER INTERACTION DISTRIBUTION")
print("="*60)
if 'User Interaction' in frequency_counts and frequency_counts['User Interaction']:
    ui_counts = frequency_counts['User Interaction']
    total_ui = sum(ui_counts.values())
    
    print("\nUser Interaction Levels:")
    ui_levels = ['NONE', 'REQUIRED', 'N/A']
    for level in ui_levels:
        count = ui_counts.get(level, 0)
        if count > 0:
            percentage = (count / total_ui) * 100
            print(f"  {level}: {count} ({percentage:.1f}%)")

# Create a summary report
print("\n" + "="*60)
print("SUMMARY STATISTICS")
print("="*60)

# Calculate coverage percentages
if files_processed > 0:
    coverage_percentage = (files_with_metrics / files_processed) * 100
    print(f"\nCVSS Metrics Coverage: {coverage_percentage:.1f}% ({files_with_metrics}/{files_processed} files)")
    
    if files_with_metrics > 0:
        v2_percentage = (cvss_v2_files / files_with_metrics) * 100
        v3_percentage = (cvss_v3_files / files_with_metrics) * 100
        print(f"CVSS v2.0 Usage: {v2_percentage:.1f}% ({cvss_v2_files}/{files_with_metrics} files)")
        print(f"CVSS v3.x Usage: {v3_percentage:.1f}% ({cvss_v3_files}/{files_with_metrics} files)")