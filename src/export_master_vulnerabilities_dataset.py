#!/usr/bin/env python3

"""
	Consolidates all scraped CVE collection files for a given project into a single master CSV file.
	Removes header-only empty files and deduplicates CVE records.
"""

import os
import glob
import pandas as pd

def consolidate_project_vulnerabilities(project_short_name: str = "glibc"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.abspath(os.path.join(script_dir, ".."))
    output_dir = os.path.join(repo_root, "Output")
    project_dir = os.path.join(output_dir, project_short_name)

    if not os.path.exists(project_dir):
        print(f"Error: Directory '{project_dir}' does not exist.")
        return

    csv_files = glob.glob(os.path.join(project_dir, "*.csv"))
    print(f"Found {len(csv_files)} CSV files in: {project_dir}")

    valid_dfs = []
    # Sort files by modification time so latest data overwrites older data during deduplication
    csv_files.sort(key=os.path.getmtime, reverse=True)

    for file_path in csv_files:
        filename = os.path.basename(file_path)
        if "vulnerabilities_master" in filename or "all_vulnerabilities" in filename:
            continue
        try:
            df = pd.read_csv(file_path)
            if not df.empty and len(df) > 0 and "CVE" in df.columns:
                valid_dfs.append(df)
                print(f"  -> Included {filename} ({len(df)} rows)")
        except Exception as e:
            print(f"  -> Skipped {filename}: {e}")

    if not valid_dfs:
        print("No non-empty vulnerability CSV files found.")
        return

    combined_df = pd.concat(valid_dfs, ignore_index=True)
    print(f"\nTotal raw records gathered across files: {len(combined_df)}")

    # Deduplicate by CVE identifier, keeping the first occurrence (from newest file)
    master_df = combined_df.drop_duplicates(subset=["CVE"], keep="first")

    # Sort by Publish Date or CVE ID if present
    if "Publish Date" in master_df.columns:
        master_df = master_df.sort_values(by="Publish Date", ascending=False)
    elif "CVE" in master_df.columns:
        master_df = master_df.sort_values(by="CVE", ascending=False)

    master_filename = f"{project_short_name}_all_vulnerabilities_master.csv"
    master_output_path = os.path.join(project_dir, master_filename)
    master_root_output_path = os.path.join(output_dir, master_filename)

    master_df.to_csv(master_output_path, index=False)
    master_df.to_csv(master_root_output_path, index=False)

    print(f"\n[SUCCESS] Consolidated {len(master_df)} unique vulnerabilities into:")
    print(f"  1. {master_output_path}")
    print(f"  2. {master_root_output_path}")

    return master_output_path


if __name__ == "__main__":
    import sys
    proj = sys.argv[1] if len(sys.argv) > 1 else "glibc"
    consolidate_project_vulnerabilities(proj)
