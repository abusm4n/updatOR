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

def find_json_files(root_folder):
    """Find all JSON files in nested folders"""
    json_files = []
    for root, dirs, files in os.walk(root_folder):
        for file in files:
            if file.endswith('.json'):
                json_files.append(os.path.join(root, file))
    return json_files

def extract_cwe_ids_from_data(data):
    """Extract CWE IDs from a JSON data object"""
    cwe_ids = set()  # Use set to avoid duplicates within same file
    
    # Check in cna container
    cna_container = data.get('containers', {}).get('cna', {})
    if cna_container:
        # Try the first format: containers.cna.problemTypes[].descriptions[].cweId
        problem_types = cna_container.get('problemTypes', [])
        for problem_type in problem_types:
            descriptions = problem_type.get('descriptions', [])
            for desc in descriptions:
                cwe_id = desc.get('cweId')
                if cwe_id:
                    # Standardize CWE format - always ensure it starts with CWE-
                    if cwe_id.startswith('CWE-'):
                        cwe_ids.add(cwe_id)
                    else:
                        cwe_ids.add(f'CWE-{cwe_id}')
    
    # Check in adp container
    adp_containers = data.get('containers', {}).get('adp', [])
    for adp in adp_containers:
        problem_types = adp.get('problemTypes', [])
        for problem_type in problem_types:
            descriptions = problem_type.get('descriptions', [])
            for desc in descriptions:
                cwe_id = desc.get('cweId')
                if cwe_id:
                    # Standardize CWE format - always ensure it starts with CWE-
                    if cwe_id.startswith('CWE-'):
                        cwe_ids.add(cwe_id)
                    else:
                        cwe_ids.add(f'CWE-{cwe_id}')
    
    return list(cwe_ids)

def process_json_files_for_cwe(folder_path):
    """Process all JSON files in the folder and extract CWE IDs"""
    cwe_counter = Counter()
    location_counter = Counter()  # Track where CWE was found
    files_with_cwe = 0
    total_files = 0
    files_processed = 0
    
    # Find all JSON files in nested folders
    print(f"Searching for JSON files in '{folder_path}' and subdirectories...")
    json_file_paths = find_json_files(folder_path)
    print(f"Found {len(json_file_paths)} JSON files to process")
    
    # Iterate over all JSON files
    for file_path in json_file_paths:
        total_files += 1
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            has_cwe = False
            found_in_cna = False
            found_in_adp = False
            
            # Check cna container
            cna_container = data.get('containers', {}).get('cna', {})
            if cna_container:
                problem_types = cna_container.get('problemTypes', [])
                for problem_type in problem_types:
                    descriptions = problem_type.get('descriptions', [])
                    for desc in descriptions:
                        cwe_id = desc.get('cweId')
                        if cwe_id:
                            has_cwe = True
                            found_in_cna = True
                            # Standardize CWE format
                            if cwe_id.startswith('CWE-'):
                                cwe_counter[cwe_id] += 1
                            else:
                                cwe_counter[f'CWE-{cwe_id}'] += 1
            
            # Check adp container
            adp_containers = data.get('containers', {}).get('adp', [])
            for adp in adp_containers:
                problem_types = adp.get('problemTypes', [])
                for problem_type in problem_types:
                    descriptions = problem_type.get('descriptions', [])
                    for desc in descriptions:
                        cwe_id = desc.get('cweId')
                        if cwe_id:
                            has_cwe = True
                            found_in_adp = True
                            # Standardize CWE format
                            if cwe_id.startswith('CWE-'):
                                cwe_counter[cwe_id] += 1
                            else:
                                cwe_counter[f'CWE-{cwe_id}'] += 1
            
            if has_cwe:
                files_with_cwe += 1
                # Track location
                if found_in_cna and found_in_adp:
                    location_counter['Both'] += 1
                elif found_in_cna:
                    location_counter['cna only'] += 1
                elif found_in_adp:
                    location_counter['adp only'] += 1
            
            files_processed += 1
            
            # Show progress
            if files_processed % 100 == 0:
                print(f"  Processed {files_processed} files... Found {files_with_cwe} with CWE IDs")
                
        except Exception as e:
            print(f"Error processing file {file_path}: {e}")
    
    return cwe_counter, location_counter, total_files, files_with_cwe, files_processed

def print_cwe_summary(cwe_counter, location_counter, total_files, files_with_cwe):
    """Print summary of CWE analysis"""
    print(f"\n{'='*60}")
    print("CWE ANALYSIS SUMMARY")
    print(f"{'='*60}")
    print(f"Total files processed: {total_files}")
    print(f"Files with CWE IDs: {files_with_cwe} ({files_with_cwe/total_files*100:.1f}%)")
    print(f"Total unique CWE IDs found: {len(cwe_counter)}")
    print(f"Total CWE occurrences: {sum(cwe_counter.values())}")
    
    print(f"\n{'='*60}")
    print("CWE ID LOCATION DISTRIBUTION")
    print(f"{'='*60}")
    for location, count in location_counter.most_common():
        percentage = (count / files_with_cwe * 100) if files_with_cwe > 0 else 0
        print(f"{location}: {count} ({percentage:.1f}%)")
    
    print(f"\n{'='*60}")
    print("ALL CWE IDS FOUND (Sorted by frequency)")
    print(f"{'='*60}")
    print(f"{'CWE ID':<15} {'Count':<10} {'% of total':<10}")
    print("-" * 40)
    
    total_cwe_occurrences = sum(cwe_counter.values())
    
    for cwe_id, count in cwe_counter.most_common():
        percentage = (count / total_cwe_occurrences * 100) if total_cwe_occurrences > 0 else 0
        print(f"{cwe_id:<15} {count:<10} {percentage:.1f}%")

def create_cwe_visualizations(cwe_counter, location_counter, total_files, files_with_cwe):
    """Create comprehensive visualizations for CWE analysis"""
    
    # Create directory for saving plots
    output_dir = './cwe_plots'
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"\nSaving all CWE plots in '{output_dir}/' folder...")
    
    # 1. TOP CWE IDs BAR CHART
    if cwe_counter:
        # Get top 20 CWE IDs (or all if less than 20)
        top_n = min(10, len(cwe_counter))
        top_cwe_items = cwe_counter.most_common(top_n)
        top_cwe_ids = [item[0] for item in top_cwe_items]
        top_cwe_counts = [item[1] for item in top_cwe_items]
        
        fig, ax = plt.subplots(figsize=(12, 8))
        
        # Create horizontal bar chart
        bars = ax.barh(range(len(top_cwe_ids)), top_cwe_counts, 
                      color=plt.cm.viridis(np.linspace(0.2, 0.8, len(top_cwe_ids))))
        
        # Add CWE IDs as labels
        ax.set_yticks(range(len(top_cwe_ids)))
        ax.set_yticklabels(top_cwe_ids, fontsize=20)
        ax.tick_params(axis='x', which='both', bottom=False, top=False, labelbottom=False)

        
        #ax.set_xlabel('Number of Occurrences', fontsize=20)
        #ax.set_title(f'Top {top_n} Most Common CWE IDs', fontsize=14, fontweight='bold')
        #ax.grid(True, alpha=0.6, axis='x')


        # 🔑 Make highest count appear at the top
        ax.invert_yaxis()
        
        # Add count labels on bars
        for i, (bar, count) in enumerate(zip(bars, top_cwe_counts)):
            width = bar.get_width()
            ax.text(width + 0.5, bar.get_y() + bar.get_height()/2, 
                   f'{count}', ha='left', va='center', fontsize=20)
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, '01_top_cwe_ids.pdf'), dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {os.path.join(output_dir, '01_top_cwe_ids.pdf')}")
        plt.close()
    
    # 2. CWE LOCATION DISTRIBUTION
    if location_counter:
        fig, ax = plt.subplots(figsize=(10, 6))
        
        locations = list(location_counter.keys())
        counts = list(location_counter.values())
        
        colors = ['#FF6B6B', '#4ECDC4', '#45B7D1']
        wedges, texts, autotexts = ax.pie(counts, labels=locations, colors=colors[:len(locations)],
                                         autopct='%1.1f%%', startangle=90, explode=[0.05]*len(locations))
        
        ax.set_title('Where CWE IDs Are Found (cna vs adp containers)', fontsize=14, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, '02_cwe_location_distribution.pdf'), dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {os.path.join(output_dir, '02_cwe_location_distribution.pdf')}")
        plt.close()
    
    # 3. CWE COVERAGE PIE CHART
    if total_files > 0:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
        
        # Coverage pie chart
        coverage_data = [files_with_cwe, total_files - files_with_cwe]
        coverage_labels = ['With CWE IDs', 'Without CWE IDs']
        coverage_colors = ['#06D6A0', '#EF476F']
        
        wedges1, texts1, autotexts1 = ax1.pie(coverage_data, labels=coverage_labels, 
                                             colors=coverage_colors, autopct='%1.1f%%',
                                             startangle=90)
        ax1.set_title('CWE ID Coverage in Files', fontsize=12, fontweight='bold')
        
        # Unique vs Total CWE IDs
        if sum(cwe_counter.values()) > 0:
            unique_cwe = len(cwe_counter)
            total_occurrences = sum(cwe_counter.values())
            duplication_rate = (total_occurrences - unique_cwe) / total_occurrences * 100
            
            stats_text = f"""
            Statistics:
            Total Files: {total_files}
            Files with CWE: {files_with_cwe}
            Unique CWE IDs: {unique_cwe}
            Total CWE Occurrences: {total_occurrences}
            Avg per file with CWE: {total_occurrences/files_with_cwe:.2f}
            Duplication Rate: {duplication_rate:.1f}%
            """
            
            ax2.text(0.1, 0.5, stats_text, fontfamily='monospace', fontsize=10,
                    verticalalignment='center', transform=ax2.transAxes,
                    bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
            ax2.axis('off')
            ax2.set_title('CWE Statistics', fontsize=12, fontweight='bold')
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, '03_cwe_coverage_stats.pdf'), dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {os.path.join(output_dir, '03_cwe_coverage_stats.pdf')}")
        plt.close()
    
    # 4. CWE FREQUENCY DISTRIBUTION (Log scale)
    if cwe_counter and len(cwe_counter) > 10:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Get all CWE counts sorted
        all_counts = sorted(cwe_counter.values(), reverse=True)
        
        # Plot 1: Rank-frequency (Zipf's law style)
        ax1.plot(range(1, len(all_counts) + 1), all_counts, 'o-', linewidth=2, markersize=4)
        ax1.set_xlabel('Rank', fontsize=12)
        ax1.set_ylabel('Frequency', fontsize=12)
        ax1.set_title('CWE Rank-Frequency Distribution', fontsize=12, fontweight='bold')
        ax1.set_xscale('log')
        ax1.set_yscale('log')
        ax1.grid(True, alpha=0.3)
        
        # Plot 2: Histogram of frequencies
        ax2.hist(all_counts, bins=20, edgecolor='black', alpha=0.7, color='#4ECDC4')
        ax2.set_xlabel('Frequency', fontsize=12)
        ax2.set_ylabel('Number of CWE IDs', fontsize=12)
        ax2.set_title('Distribution of CWE Frequencies', fontsize=12, fontweight='bold')
        ax2.grid(True, alpha=0.3, axis='y')
        
        plt.suptitle('CWE Frequency Analysis', fontsize=14, fontweight='bold', y=1.02)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, '04_cwe_frequency_analysis.pdf'), dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {os.path.join(output_dir, '04_cwe_frequency_analysis.pdf')}")
        plt.close()
    
    # 5. ALL CWE IDs BAR CHART (if not too many)
    if cwe_counter and len(cwe_counter) <= 50:
        fig, ax = plt.subplots(figsize=(14, 10))
        
        # Get all CWE IDs sorted by count
        all_cwe_items = cwe_counter.most_common()
        all_cwe_ids = [item[0] for item in all_cwe_items]
        all_cwe_counts = [item[1] for item in all_cwe_items]
        
        bars = ax.barh(range(len(all_cwe_ids)), all_cwe_counts, 
                      color=plt.cm.plasma(np.linspace(0.2, 0.8, len(all_cwe_ids))))
        
        ax.set_yticks(range(len(all_cwe_ids)))
        ax.set_yticklabels(all_cwe_ids, fontsize=8)
        ax.set_xlabel('Number of Occurrences', fontsize=12)
        ax.set_title(f'All {len(all_cwe_ids)} CWE IDs Found (Sorted by Frequency)', fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='x')
        
        # Add count labels on bars
        for i, (bar, count) in enumerate(zip(bars, all_cwe_counts)):
            width = bar.get_width()
            ax.text(width + 0.5, bar.get_y() + bar.get_height()/2, 
                   f'{count}', ha='left', va='center', fontsize=8)
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, '05_all_cwe_ids.pdf'), dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {os.path.join(output_dir, '05_all_cwe_ids.pdf')}")
        plt.close()
    
    print(f"\n✅ All CWE visualizations saved to '{output_dir}/'")
    print(f"📊 Generated files:")
    for plot_file in sorted([f for f in os.listdir(output_dir) if f.endswith('.pdf')]):
        print(f"   - {plot_file}")

def save_cwe_data_to_csv(cwe_counter, location_counter, output_file='cwe_analysis.csv'):
    """Save CWE analysis data to CSV file"""
    
    # Prepare data for CSV
    data = []
    
    # Add CWE frequency data
    for cwe_id, count in cwe_counter.most_common():
        percentage = (count / sum(cwe_counter.values()) * 100) if sum(cwe_counter.values()) > 0 else 0
        data.append({
            'CWE_ID': cwe_id,
            'Count': count,
            'Percentage': f"{percentage:.2f}%"
        })
    
    # Add summary statistics
    if cwe_counter:
        data.append({
            'CWE_ID': 'SUMMARY STATISTICS',
            'Count': '',
            'Percentage': ''
        })
        data.append({
            'CWE_ID': 'Total Unique CWE IDs',
            'Count': len(cwe_counter),
            'Percentage': ''
        })
        data.append({
            'CWE_ID': 'Total CWE Occurrences',
            'Count': sum(cwe_counter.values()),
            'Percentage': ''
        })
    
    # Add location data to separate sheet or file
    location_data = []
    for location, count in location_counter.most_common():
        percentage = (count / sum(location_counter.values()) * 100) if sum(location_counter.values()) > 0 else 0
        location_data.append({
            'Location': location,
            'Count': count,
            'Percentage': f"{percentage:.2f}%"
        })
    
    # Create DataFrames and save to CSV
    df_cwe = pd.DataFrame(data)
    df_location = pd.DataFrame(location_data)
    
    # Save to separate CSV files
    df_cwe.to_csv('cwe_frequency.csv', index=False)
    df_location.to_csv('cwe_locations.csv', index=False)
    
    print(f"\n📁 CWE frequency data saved to 'cwe_frequency.csv'")
    print(f"📁 CWE location data saved to 'cwe_locations.csv'")
    
    return df_cwe, df_location

# Main execution
if __name__ == "__main__":
    # Folder containing the dataset
    # Choose one of these paths based on your data location
    # dataset_folder = './data/data_sw'
    # dataset_folder = './data/data_fw'
    #dataset_folder = './data/both'
    dataset_folder = './data/overall'  # Adjust this path as needed
    
    print("="*60)
    print("CWE (Common Weakness Enumeration) ANALYSIS")
    print("="*60)
    
    # Process the JSON files and extract CWE IDs
    cwe_counter, location_counter, total_files, files_with_cwe, files_processed = process_json_files_for_cwe(dataset_folder)
    
    # Print summary - showing all CWE IDs separately
    print_cwe_summary(cwe_counter, location_counter, total_files, files_with_cwe)
    
    # Print detailed breakdown of all CWE IDs
    print(f"\n{'='*60}")
    print("DETAILED CWE ID BREAKDOWN")
    print(f"{'='*60}")
    
    total_cwe_occurrences = sum(cwe_counter.values())
    print(f"\nAll CWE IDs found ({len(cwe_counter)} unique):")
    print("-" * 80)
    
    # Print each CWE ID with its stats
    for i, (cwe_id, count) in enumerate(cwe_counter.most_common(), 1):
        percentage = (count / total_cwe_occurrences * 100) if total_cwe_occurrences > 0 else 0
        print(f"{i:3}. {cwe_id:<15} {count:>6} occurrences ({percentage:.2f}%)")
    
    # Create visualizations
    print("\n" + "="*60)
    print("GENERATING CWE VISUALIZATIONS")
    print("="*60)
    
    create_cwe_visualizations(cwe_counter, location_counter, total_files, files_with_cwe)
    
    # Save data to CSV
    print("\n" + "="*60)
    print("SAVING DATA TO CSV FILES")
    print("="*60)
    
    df_cwe, df_location = save_cwe_data_to_csv(cwe_counter, location_counter)
    
    # Print additional detailed statistics
    print("\n" + "="*60)
    print("DETAILED STATISTICS")
    print("="*60)
    
    if sum(cwe_counter.values()) > 0:
        print(f"\nSummary Statistics:")
        print(f"- Files with CWE IDs: {files_with_cwe}/{total_files} ({files_with_cwe/total_files*100:.1f}%)")
        print(f"- Average CWE occurrences per vulnerable file: {sum(cwe_counter.values())/files_with_cwe:.2f}")
        
        # Most common CWE IDs
        print(f"\nMost Common CWE IDs:")
        for i, (cwe_id, count) in enumerate(cwe_counter.most_common(5), 1):
            percentage = (count / sum(cwe_counter.values()) * 100)
            print(f"  {i}. {cwe_id}: {count} occurrences ({percentage:.1f}%)")
        
        # Calculate diversity metrics
        if len(cwe_counter) > 0:
            # Calculate entropy (Shannon diversity index)
            probs = [count/sum(cwe_counter.values()) for count in cwe_counter.values()]
            entropy = -sum(p * np.log(p) for p in probs)
            
            # Calculate Gini coefficient
            sorted_counts = sorted(cwe_counter.values())
            n = len(sorted_counts)
            cumulative_counts = np.cumsum(sorted_counts)
            gini = (n + 1 - 2 * np.sum(cumulative_counts) / cumulative_counts[-1]) / n if cumulative_counts[-1] > 0 else 0
            
            print(f"\nDiversity Metrics:")
            print(f"- Shannon diversity index: {entropy:.3f}")
            print(f"- Gini coefficient (inequality): {gini:.3f}")
            print(f"- Simpson's diversity index: {1 - sum(p**2 for p in probs):.3f}")
    
    print("\n" + "='*60")
    print("ANALYSIS COMPLETE")
    print("="*60)