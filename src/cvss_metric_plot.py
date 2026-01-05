import os
import json
from collections import Counter
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib import cm
import warnings
warnings.filterwarnings('ignore')

# Set style for better looking plots
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")

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


def normalize_impact(value):
    """Normalize CVSS CIA impact values"""
    if value is None:
        return 'N/A'
    v = str(value).upper()
    if v in ['H', 'HIGH']:
        return 'HIGH'
    if v in ['L', 'LOW']:
        return 'LOW'
    if v in ['N', 'NONE']:
        return 'NONE'
    if v in ['M', 'MEDIUM']:
        return 'MEDIUM'
    return 'N/A'


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

def find_json_files(root_folder):
    """Find all JSON files in nested folders"""
    json_files = []
    for root, dirs, files in os.walk(root_folder):
        for file in files:
            if file.endswith('.json'):
                json_files.append(os.path.join(root, file))
    return json_files

def process_json_files(folder_path):
    """Process all JSON files in the folder and extract CVSS metrics"""
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
                            if key in ['Confidentiality', 'Integrity', 'Availability']:
                                value = normalize_impact(value)
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
                                    if key in ['Confidentiality', 'Integrity', 'Availability']:
                                        value = normalize_impact(value)
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

def create_visualizations(frequency_counts, total_files, files_with_metrics, cvss_v2_files, cvss_v3_files):
    """Create comprehensive visualizations for CVSS metrics and save as high-quality PDFs"""
    
    # Create directory for saving plots
    output_dir = './cvss_plots_pdf'
    os.makedirs(output_dir, exist_ok=True)
    
    # Set PDF saving parameters for highest quality
    pdf_kwargs = {
        'format': 'pdf',
        'dpi': 300,  # High resolution
        'bbox_inches': 'tight',
        'pad_inches': 0.1,
        'transparent': False
    }
    
    # Set figure parameters for publication quality
    plt.rcParams.update({
        'figure.dpi': 300,
        'savefig.dpi': 300,
        'font.size': 10,
        'axes.titlesize': 12,
        'axes.labelsize': 11,
        'xtick.labelsize': 10,
        'ytick.labelsize': 10,
        'legend.fontsize': 9,
        'figure.titlesize': 14,
        'pdf.fonttype': 42,  # Ensures text is editable in PDF
        'ps.fonttype': 42,
        'font.family': 'sans-serif',
        'font.sans-serif': ['Arial', 'DejaVu Sans', 'Helvetica'],
    })
    
    print(f"\nSaving all plots as high-quality PDFs in '{output_dir}/' folder...")
    
    # 1. SEVERITY LEVEL PIE CHART (Most Important)
    if 'SeverityLevel' in frequency_counts and frequency_counts['SeverityLevel']:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Pie chart for SeverityLevel
        severity_data = frequency_counts['SeverityLevel']
        # Filter out N/A and get non-zero values
        labels = [k for k in severity_data.keys() if k != 'N/A' and severity_data[k] > 0]
        sizes = [severity_data[k] for k in labels]
        
        if sizes:  # Only create chart if we have data
            # Define color mapping for severity levels
            color_map = {
                'Critical': '#FF6B6B',  # Red
                'High': '#FF9B71',      # Orange-red
                'Medium': '#FFD166',     # Yellow
                'Low': '#06D6A0'        # Green
            }
            
            colors = [color_map.get(label, '#118AB2') for label in labels]
            
            ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                    startangle=90, shadow=True, explode=[0.05]*len(labels))
            ax1.set_title('CVSS Severity Distribution', fontsize=14, fontweight='bold')
            ax1.axis('equal')
            
            # Bar chart for comparison
            bars = ax2.bar(labels, sizes, color=colors, edgecolor='black', linewidth=1.5)
            ax2.set_title('CVSS Severity Counts', fontsize=14, fontweight='bold')
            ax2.set_xlabel('Severity Level', fontsize=12)
            ax2.set_ylabel('Count', fontsize=12)
            ax2.grid(True, alpha=0.3, axis='y')
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                        f'{int(height)}', ha='center', va='bottom', fontweight='bold')
            
            plt.tight_layout()
            # Save as PDF
            pdf_path = os.path.join(output_dir, '01_severity_distribution.pdf')
            plt.savefig(pdf_path, **pdf_kwargs)
            print(f"✓ Saved: {pdf_path}")
            plt.close(fig)
    
    # 2. CIA TRIAD RADAR CHART
    cia_metrics = ['Confidentiality', 'Integrity', 'Availability']
    cia_data = {}
    
    for metric in cia_metrics:
        if metric in frequency_counts and frequency_counts[metric]:
            counts = frequency_counts[metric]
            # Calculate percentage of HIGH impacts
            total = sum(counts.values())
            high_count = counts.get('HIGH', 0) + counts.get('CRITICAL', 0)  # Include CRITICAL if present
            if total > 0:
                cia_data[metric] = (high_count / total) * 100
    
    if cia_data:
        fig = plt.figure(figsize=(8, 8))
        ax = fig.add_subplot(111, projection='polar')
        
        categories = list(cia_data.keys())
        N = len(categories)
        
        # Duplicate first value to close the circle
        values = list(cia_data.values())
        values += values[:1]
        
        # Calculate angles
        angles = [n / float(N) * 2 * np.pi for n in range(N)]
        angles += angles[:1]
        
        # Plot
        ax.plot(angles, values, 'o-', linewidth=2, color='#4A90E2', markersize=8)
        ax.fill(angles, values, alpha=0.25, color='#4A90E2')
        
        # Set labels
        ax.set_xticks(angles[:-1])
        ax.set_xticklabels(categories, fontsize=12, fontweight='bold')
        ax.set_ylim(0, 100)
        ax.set_yticks([0, 25, 50, 75, 100])
        ax.set_yticklabels(['0%', '25%', '50%', '75%', '100%'], fontsize=10)
        ax.set_title('CIA Triad - Percentage of HIGH Impact Vulnerabilities', 
                    fontsize=14, fontweight='bold', pad=20)
        ax.grid(True)
        
        plt.tight_layout()
        # Save as PDF
        pdf_path = os.path.join(output_dir, '02_cia_triad_radar.pdf')
        plt.savefig(pdf_path, **pdf_kwargs)
        print(f"✓ Saved: {pdf_path}")
        plt.close(fig)
    
    # 3. ATTACK VECTOR & COMPLEXITY BAR CHART - FIXED VERSION
    fig, axes = plt.subplots(1, 2, figsize=(14, 6))
    
    plot_created = False  # Track if any plot was created
    
    # Attack Vector
    if 'Attack Vector' in frequency_counts and frequency_counts['Attack Vector']:
        av_counts = frequency_counts['Attack Vector']
        
        # Process attack vector data
        av_mapping = {
            'N': 'Network', 'NETWORK': 'Network',
            'A': 'Adjacent', 'ADJACENT_NETWORK': 'Adjacent',
            'L': 'Local', 'LOCAL': 'Local',
            'P': 'Physical', 'PHYSICAL': 'Physical'
        }
        
        av_labels = []
        av_values = []
        
        # Aggregate counts for each type
        for readable_name in ['Network', 'Adjacent', 'Local', 'Physical']:
            count = 0
            for key, value in av_counts.items():
                key_str = str(key).upper()
                if readable_name.upper() in key_str:
                    count += value
                elif key in av_mapping and av_mapping[key] == readable_name:
                    count += value
                elif key_str in ['N', 'A', 'L', 'P']:
                    # Map single letters
                    letter_map = {'N': 'Network', 'A': 'Adjacent', 'L': 'Local', 'P': 'Physical'}
                    if key_str in letter_map and letter_map[key_str] == readable_name:
                        count += value
            
            if count > 0:
                av_labels.append(readable_name)
                av_values.append(count)
        
        if av_values:  # Only plot if we have data
            bars1 = axes[0].bar(av_labels, av_values, color=['#FF6B6B', '#FFD166', '#06D6A0', '#118AB2'][:len(av_labels)])
            axes[0].set_title('Attack Vector Distribution', fontsize=14, fontweight='bold')
            axes[0].set_xlabel('Attack Vector', fontsize=12)
            axes[0].set_ylabel('#Vulnerabilities', fontsize=12)
            axes[0].tick_params(axis='x', rotation=0)
            axes[0].grid(True, alpha=0.3, axis='y')
            
            for bar in bars1:
                height = bar.get_height()
                axes[0].text(bar.get_x() + bar.get_width()/2., height + 0.5,
                        f'{int(height)}', ha='center', va='bottom', fontweight='bold')
            plot_created = True
    else:
        axes[0].text(0.5, 0.5, 'No Attack Vector Data', 
                    ha='center', va='center', fontsize=12, fontweight='bold')
        axes[0].set_title('Attack Vector Distribution', fontsize=14, fontweight='bold')
        axes[0].axis('off')
    
    # Attack Complexity - FIXED
    if 'Attack Complexity' in frequency_counts and frequency_counts['Attack Complexity']:
        ac_counts = frequency_counts['Attack Complexity']
        
        # Clean and process attack complexity data
        ac_labels = []
        ac_values = []
        
        # Standardize labels
        standardized_counts = Counter()
        for key, count in ac_counts.items():
            key_str = str(key).upper()
            if 'LOW' in key_str or key_str == 'L':
                standardized_counts['LOW'] += count
            elif 'HIGH' in key_str or key_str == 'H':
                standardized_counts['HIGH'] += count
            elif key_str != 'N/A':
                # For any other values
                standardized_counts[key_str] += count
        
        # Get sorted values
        for label in ['LOW', 'HIGH']:
            count = standardized_counts.get(label, 0)
            if count > 0:
                ac_labels.append(label)
                ac_values.append(count)
        
        # Add any other values
        for label, count in standardized_counts.items():
            if label not in ['LOW', 'HIGH', 'N/A'] and count > 0:
                ac_labels.append(label)
                ac_values.append(count)
        
        if ac_values:  # Only plot if we have data
            # Use appropriate colors
            color_map = {'LOW': '#06D6A0', 'HIGH': '#FF6B6B'}  # Green for LOW, Red for HIGH
            colors = [color_map.get(label.upper(), '#118AB2') for label in ac_labels]
            
            bars2 = axes[1].bar(ac_labels, ac_values, color=colors)
            axes[1].set_title('Attack Complexity Distribution', fontsize=14, fontweight='bold')
            axes[1].set_xlabel('Attack Complexity', fontsize=12)
            axes[1].set_ylabel('#Vulnerabilities', fontsize=12)
            axes[1].grid(True, alpha=0.3, axis='y')
            
            for bar in bars2:
                height = bar.get_height()
                axes[1].text(bar.get_x() + bar.get_width()/2., height + 0.5,
                        f'{int(height)}', ha='center', va='bottom', fontweight='bold')
            plot_created = True
    else:
        axes[1].text(0.5, 0.5, 'No Attack Complexity Data', 
                    ha='center', va='center', fontsize=12, fontweight='bold')
        axes[1].set_title('Attack Complexity Distribution', fontsize=14, fontweight='bold')
        axes[1].axis('off')
    
    if plot_created:
        plt.tight_layout()
        # Save as PDF
        pdf_path = os.path.join(output_dir, '03_attack_metrics.pdf')
        plt.savefig(pdf_path, **pdf_kwargs)
        print(f"✓ Saved: {pdf_path}")
    plt.close(fig)
    
    # 4. CVSS VERSION & METRICS COVERAGE
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    plot_created = False
    
    # CVSS Version Usage
    if files_with_metrics > 0 and (cvss_v2_files > 0 or cvss_v3_files > 0):
        versions = []
        version_counts = []
        
        if cvss_v2_files > 0:
            versions.append('CVSS v2.0')
            version_counts.append(cvss_v2_files)
        if cvss_v3_files > 0:
            versions.append('CVSS v3.x')
            version_counts.append(cvss_v3_files)
        
        version_colors = ['#FFD166', '#118AB2'][:len(versions)]
        
        wedges, texts, autotexts = ax1.pie(version_counts, labels=versions, colors=version_colors,
                                           autopct='%1.1f%%', startangle=90, explode=[0.05]*len(versions))
        ax1.set_title('CVSS Version Usage', fontsize=14, fontweight='bold')
        
        # Make autopct bold
        for autotext in autotexts:
            autotext.set_color('white')
            autotext.set_fontweight('bold')
        plot_created = True
    else:
        ax1.text(0.5, 0.5, 'No CVSS Version Data', 
                ha='center', va='center', fontsize=12, fontweight='bold')
        ax1.set_title('CVSS Version Usage', fontsize=14, fontweight='bold')
        ax1.axis('off')
    
    # Metrics Coverage
    if total_files > 0:
        coverage_data = {
            'With CVSS Metrics': files_with_metrics,
            'Without CVSS Metrics': total_files - files_with_metrics
        }
        
        colors = ['#06D6A0', '#EF476F']
        bars = ax2.bar(list(coverage_data.keys()), list(coverage_data.values()), 
                      color=colors, edgecolor='black', linewidth=1.5)
        ax2.set_title('CVSS Metrics Coverage', fontsize=14, fontweight='bold')
        ax2.set_ylabel('Number of Files', fontsize=12)
        ax2.grid(True, alpha=0.3, axis='y')
        
        for bar in bars:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                    f'{int(height)}', ha='center', va='bottom', fontweight='bold')
        plot_created = True
    else:
        ax2.text(0.5, 0.5, 'No Coverage Data', 
                ha='center', va='center', fontsize=12, fontweight='bold')
        ax2.set_title('CVSS Metrics Coverage', fontsize=14, fontweight='bold')
        ax2.axis('off')
    
    if plot_created:
        plt.tight_layout()
        # Save as PDF
        pdf_path = os.path.join(output_dir, '04_coverage_versions.pdf')
        plt.savefig(pdf_path, **pdf_kwargs)
        print(f"✓ Saved: {pdf_path}")
    plt.close(fig)
    
    # 5. CIA IMPACT LEVELS DETAILED
    cia_metrics = ['Confidentiality', 'Integrity', 'Availability']
    has_cia_data = False
    
    for metric in cia_metrics:
        if metric in frequency_counts and frequency_counts[metric]:
            has_cia_data = True
            break
    
    if has_cia_data:
        fig, axes = plt.subplots(1, 3, figsize=(15, 5))
        
        for idx, metric in enumerate(cia_metrics):
            if idx < 3 and metric in frequency_counts and frequency_counts[metric]:
                counts = frequency_counts[metric]
                total = sum(counts.values())
                
                if total > 0:
                    # Prepare data for bar chart
                    levels = ['HIGH', 'MEDIUM', 'LOW', 'NONE']
                    level_counts = []
                    level_labels = []
                    
                    for level in levels:
                        count = counts.get(level, 0)
                        if count > 0:
                            level_counts.append(count)
                            level_labels.append(level)
                    
                    if level_counts:
                        colors_map = {
                            'HIGH': '#E74C3C',
                            'MEDIUM': '#F1C40F',
                            'LOW': '#3498DB',
                            'NONE': '#95A5A6'
                        }
                        
                        colors = [colors_map.get(label, '#95A5A6') for label in level_labels]
                        
                        bars = axes[idx].bar(level_labels, level_counts, color=colors, edgecolor='black')
                        axes[idx].set_title(f'{metric} Impact', fontsize=12, fontweight='bold')
                        axes[idx].set_xlabel('Impact Level', fontsize=10)
                        axes[idx].set_ylabel('#Vulnerabilities', fontsize=10)
                        axes[idx].grid(True, alpha=0.3, axis='y')
                        
                        for bar in bars:
                            height = bar.get_height()
                            axes[idx].text(bar.get_x() + bar.get_width()/2., height + 0.5,
                                    f'{int(height)}', ha='center', va='bottom', fontsize=9, fontweight='bold')
                    else:
                        axes[idx].text(0.5, 0.5, 'No Data', 
                                      ha='center', va='center', fontsize=10)
                        axes[idx].set_title(f'{metric} Impact', fontsize=12, fontweight='bold')
                        axes[idx].axis('off')
                else:
                    axes[idx].text(0.5, 0.5, 'No Data', 
                                  ha='center', va='center', fontsize=10)
                    axes[idx].set_title(f'{metric} Impact', fontsize=12, fontweight='bold')
                    axes[idx].axis('off')
            else:
                axes[idx].text(0.5, 0.5, 'No Data', 
                              ha='center', va='center', fontsize=10)
                axes[idx].set_title(f'{metric} Impact', fontsize=12, fontweight='bold')
                axes[idx].axis('off')
        
        plt.suptitle('CIA Impact Levels Detailed Breakdown', fontsize=14, fontweight='bold', y=1.05)
        plt.tight_layout()
        # Save as PDF
        pdf_path = os.path.join(output_dir, '05_cia_detailed.pdf')
        plt.savefig(pdf_path, **pdf_kwargs)
        print(f"✓ Saved: {pdf_path}")
        plt.close(fig)
    
    # 6. COMPREHENSIVE DASHBOARD
    fig = plt.figure(figsize=(16, 10))
    
    # Create subplot grid
    gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)
    
    # 6a. Severity Pie Chart (Top Left)
    if 'SeverityLevel' in frequency_counts and frequency_counts['SeverityLevel']:
        ax1 = fig.add_subplot(gs[0, 0])
        severity_data = frequency_counts['SeverityLevel']
        labels = [k for k in severity_data.keys() if k != 'N/A' and severity_data[k] > 0]
        sizes = [severity_data[k] for k in labels]
        
        if sizes:
            ax1.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
            ax1.set_title('Severity Distribution', fontweight='bold', fontsize=11)
        else:
            ax1.text(0.5, 0.5, 'No Severity Data', 
                    ha='center', va='center', fontsize=10, fontweight='bold')
            ax1.set_title('Severity Distribution', fontweight='bold', fontsize=11)
            ax1.axis('off')
    else:
        ax1 = fig.add_subplot(gs[0, 0])
        ax1.text(0.5, 0.5, 'No Severity Data', 
                ha='center', va='center', fontsize=10, fontweight='bold')
        ax1.set_title('Severity Distribution', fontweight='bold', fontsize=11)
        ax1.axis('off')
    
    # 6b. CIA Triad Summary (Top Middle)
    ax2 = fig.add_subplot(gs[0, 1])
    
    if all(m in frequency_counts for m in ['Confidentiality', 'Integrity', 'Availability']):
        cia_high_counts = []
        valid_metrics = []
        
        for metric in ['Confidentiality', 'Integrity', 'Availability']:
            counts = frequency_counts[metric]
            total = sum(counts.values())
            high_count = counts.get('HIGH', 0) + counts.get('CRITICAL', 0)
            if total > 0:
                cia_high_counts.append((high_count / total) * 100)
                valid_metrics.append(metric)
        
        if cia_high_counts:
            bars = ax2.bar(valid_metrics, cia_high_counts,
                          color=['#E74C3C', '#3498DB', '#2ECC71'][:len(valid_metrics)])
            ax2.set_title('CIA - % High Impact', fontweight='bold', fontsize=11)
            ax2.set_ylabel('Percentage (%)', fontsize=9)
            ax2.set_ylim(0, 100)
            ax2.grid(True, alpha=0.3, axis='y')
            
            for bar in bars:
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height + 1,
                        f'{height:.1f}%', ha='center', va='bottom', fontsize=8)
        else:
            ax2.text(0.5, 0.5, 'No CIA Data', 
                    ha='center', va='center', fontsize=10, fontweight='bold')
            ax2.set_title('CIA - % High Impact', fontweight='bold', fontsize=11)
            ax2.axis('off')
    else:
        ax2.text(0.5, 0.5, 'No CIA Data', 
                ha='center', va='center', fontsize=10, fontweight='bold')
        ax2.set_title('CIA - % High Impact', fontweight='bold', fontsize=11)
        ax2.axis('off')
    
    # 6c. Attack Vector (Top Right)
    ax3 = fig.add_subplot(gs[0, 2])
    
    if 'Attack Vector' in frequency_counts and frequency_counts['Attack Vector']:
        av_counts = frequency_counts['Attack Vector']
        
        # Simplify labels
        av_simple = {'Network': 0, 'Adjacent': 0, 'Local': 0, 'Physical': 0}
        for key, count in av_counts.items():
            key_str = str(key).upper()
            if 'NETWORK' in key_str or key_str == 'N':
                av_simple['Network'] += count
            elif 'ADJACENT' in key_str or key_str == 'A':
                av_simple['Adjacent'] += count
            elif 'LOCAL' in key_str or key_str == 'L':
                av_simple['Local'] += count
            elif 'PHYSICAL' in key_str or key_str == 'P':
                av_simple['Physical'] += count
        
        # Filter out zero values
        av_filtered = {k: v for k, v in av_simple.items() if v > 0}
        if av_filtered:
            bars = ax3.bar(list(av_filtered.keys()), list(av_filtered.values()))
            ax3.set_title('Attack Vector', fontweight='bold', fontsize=11)
            ax3.set_ylabel('Count', fontsize=9)
            ax3.tick_params(axis='x', rotation=0)
            ax3.grid(True, alpha=0.3, axis='y')
        else:
            ax3.text(0.5, 0.5, 'No Attack Vector Data', 
                    ha='center', va='center', fontsize=10, fontweight='bold')
            ax3.set_title('Attack Vector', fontweight='bold', fontsize=11)
            ax3.axis('off')
    else:
        ax3.text(0.5, 0.5, 'No Attack Vector Data', 
                ha='center', va='center', fontsize=10, fontweight='bold')
        ax3.set_title('Attack Vector', fontweight='bold', fontsize=11)
        ax3.axis('off')
    
    # 6d. Metrics Coverage (Middle)
    ax4 = fig.add_subplot(gs[1, :])
    
    metrics_stats = []
    metric_names = []
    
    for metric in ['Confidentiality', 'Integrity', 'Availability', 
                   'Attack Vector', 'Attack Complexity', 'User Interaction']:
        if metric in frequency_counts:
            total = sum(frequency_counts[metric].values())
            if total > 0:
                metrics_stats.append(total)
                metric_names.append(metric)
    
    if metrics_stats:
        bars = ax4.bar(metric_names, metrics_stats, color='steelblue')
        ax4.set_title('Metrics Coverage (Total Entries)', fontweight='bold', fontsize=11)
        ax4.set_ylabel('Count', fontsize=9)
        ax4.tick_params(axis='x', rotation=0)
        ax4.grid(True, alpha=0.3, axis='y')
        
        for bar in bars:
            height = bar.get_height()
            ax4.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                    f'{int(height)}', ha='center', va='bottom', fontsize=8)
    else:
        ax4.text(0.5, 0.5, 'No Metrics Coverage Data', 
                ha='center', va='center', fontsize=10, fontweight='bold')
        ax4.set_title('Metrics Coverage (Total Entries)', fontweight='bold', fontsize=11)
        ax4.axis('off')
    
    # 6e. Summary Statistics (Bottom)
    ax5 = fig.add_subplot(gs[2, :])
    ax5.axis('off')
    
    # Create text summary
    summary_text = f"""
    CVSS Metrics Analysis Summary
    {'='*40}
    Total Files Analyzed: {total_files}
    Files with CVSS Metrics: {files_with_metrics} ({files_with_metrics/total_files*100:.1f}%)
    CVSS v2.0 Files: {cvss_v2_files} ({cvss_v2_files/files_with_metrics*100:.1f}% of metrics)
    CVSS v3.x Files: {cvss_v3_files} ({cvss_v3_files/files_with_metrics*100:.1f}% of metrics)
    
    Top Severity: {max(frequency_counts.get('SeverityLevel', {}).items(), key=lambda x: x[1])[0] if frequency_counts.get('SeverityLevel') else 'N/A'}
    Most Common Attack Vector: {max(frequency_counts.get('Attack Vector', {}).items(), key=lambda x: x[1])[0] if frequency_counts.get('Attack Vector') else 'N/A'}
    Most Common Attack Complexity: {max(frequency_counts.get('Attack Complexity', {}).items(), key=lambda x: x[1])[0] if frequency_counts.get('Attack Complexity') else 'N/A'}
    """
    
    ax5.text(0.1, 0.5, summary_text, fontfamily='monospace', fontsize=9,
            verticalalignment='center', transform=ax5.transAxes,
            bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.suptitle('CVSS Metrics Dashboard', fontsize=16, fontweight='bold', y=0.98)
    plt.tight_layout()
    # Save as PDF
    pdf_path = os.path.join(output_dir, '06_comprehensive_dashboard.pdf')
    plt.savefig(pdf_path, **pdf_kwargs)
    print(f"✓ Saved: {pdf_path}")
    plt.close(fig)
    
    # 7. CREATE A SUMMARY TABLE AS FIGURE
    if frequency_counts:
        # Prepare data for summary table
        metrics_for_table = ['SeverityLevel', 'Confidentiality', 'Integrity', 'Availability', 
                           'Attack Vector', 'Attack Complexity', 'User Interaction']
        
        table_data = []
        for metric in metrics_for_table:
            if metric in frequency_counts and frequency_counts[metric]:
                counts = frequency_counts[metric]
                total = sum(counts.values())
                
                # Get top 3 values
                top_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:3]
                top_str = ", ".join([f"{k}: {v} ({v/total*100:.1f}%)" for k, v in top_items if k != 'N/A'])
                
                table_data.append([metric, total, top_str])
        
        if table_data:
            fig, ax = plt.subplots(figsize=(12, len(table_data) * 0.5 + 2))
            ax.axis('tight')
            ax.axis('off')
            
            # Create table
            table = ax.table(cellText=table_data,
                           colLabels=['Metric', 'Total', 'Top 3 Values (with %)'],
                           cellLoc='left',
                           loc='center',
                           colWidths=[0.25, 0.15, 0.6])
            
            # Style the table
            table.auto_set_font_size(False)
            table.set_fontsize(9)
            table.scale(1, 1.5)
            
            # Color header
            for i in range(3):
                table[(0, i)].set_facecolor('#4A90E2')
                table[(0, i)].set_text_props(weight='bold', color='white')
            
            # Alternate row colors
            for i in range(1, len(table_data) + 1):
                if i % 2 == 0:
                    for j in range(3):
                        table[(i, j)].set_facecolor('#f2f2f2')
            
            ax.set_title('CVSS Metrics Summary Table', fontsize=14, fontweight='bold', pad=20)
            
            plt.tight_layout()
            # Save as PDF
            pdf_path = os.path.join(output_dir, '07_summary_table.pdf')
            plt.savefig(pdf_path, **pdf_kwargs)
            print(f"✓ Saved: {pdf_path}")
            plt.close(fig)
    
    print(f"\n✅ All {len([f for f in os.listdir(output_dir) if f.endswith('.pdf')])} PDFs saved successfully to '{output_dir}/'")
    print(f"📊 Generated PDF files:")
    for pdf_file in sorted([f for f in os.listdir(output_dir) if f.endswith('.pdf')]):
        print(f"   - {pdf_file}")

# Main execution
if __name__ == "__main__":
    # Folder containing the dataset
    #dataset_folder = './data/data_sw'
    #dataset_folder = './data/data_fw'
    dataset_folder = './data/both'
    #dataset_folder = './data/overall'


    
    # Process the JSON files and get the frequency counts
    print("="*60)
    print("PROCESSING CVSS METRICS DATA")
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

    # Attack Complexity breakdown
    print("\n" + "="*60)
    print("ATTACK COMPLEXITY DISTRIBUTION")
    print("="*60)
    if 'Attack Complexity' in frequency_counts and frequency_counts['Attack Complexity']:
        ac_counts = frequency_counts['Attack Complexity']
        total_ac = sum(ac_counts.values())
        
        print("\nAttack Complexity Breakdown:")
        # Standardize labels for printing
        standardized_counts = Counter()
        for key, count in ac_counts.items():
            key_str = str(key).upper()
            if 'LOW' in key_str or key_str == 'L':
                standardized_counts['LOW'] += count
            elif 'HIGH' in key_str or key_str == 'H':
                standardized_counts['HIGH'] += count
            elif key_str != 'N/A':
                standardized_counts[key_str] += count
        
        for label, count in standardized_counts.items():
            if count > 0:
                percentage = (count / total_ac) * 100
                print(f"  {label}: {count} ({percentage:.1f}%)")

    # Severity Level breakdown
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

    # Create a summary report
    print("\n" + "="*60)
    print("SUMMARY STATISTICS")
    print("="*60)

    # Calculate coverage percentages
    if files_processed > 0:
        coverage_percentage = (files_with_metrics / files_processed) * 100
        print(f"\nCVSS Metrics Coverage: {coverage_percentage:.1f}% ({files_with_metrics}/{files_processed} files)")
        
        if files_with_metrics > 0:
            if cvss_v2_files > 0:
                v2_percentage = (cvss_v2_files / files_with_metrics) * 100
                print(f"CVSS v2.0 Usage: {v2_percentage:.1f}% ({cvss_v2_files}/{files_with_metrics} files)")
            if cvss_v3_files > 0:
                v3_percentage = (cvss_v3_files / files_with_metrics) * 100
                print(f"CVSS v3.x Usage: {v3_percentage:.1f}% ({cvss_v3_files}/{files_with_metrics} files)")
    
    # Generate visualizations
    print("\n" + "="*60)
    print("GENERATING VISUALIZATIONS")
    print("="*60)
    
    create_visualizations(frequency_counts, total_files, files_with_metrics, cvss_v2_files, cvss_v3_files)