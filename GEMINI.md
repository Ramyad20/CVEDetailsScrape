# Project Context & Gemini Instructions: CVEDetailsScrape Pipeline

## 1. Golden Rule: Clean Workspace & Temporary Files Policy
* **Automatic Cleanup**: Never leave temporary files, extraction dumps, intermediate `.txt`, `.html`, or scratch scripts lying around in the workspace directories.
* **Agent Scratch Space**: If intermediate files or one-off scripts are needed for parsing or inspection, store them exclusively in the agent's scratch directory (`<appDataDir>/brain/<conversation-id>/scratch/`) or delete them immediately after use before completing the turn.
* **Zero Residual Artifacts**: Always ensure `git status` remains clean and free of untracked temporary files after running operations.

## 2. Security & Credentials Policy
* **No Plain-text Secrets**: Never hardcode, commit, or stage passwords, OAuth credentials, or personal email addresses in source code or template configs.
* **Environment Variables**: Always load sensitive credentials dynamically using `os.getenv(...)` via `.env`.
* **Placeholder Integrity**: Keep placeholders intact in template configuration files (e.g., `<Username>`, `<Password>`, `<DB_User>`, `<DB_Password>`, `<Email_From>`, `<Email_Password>`).
* **Git Ignore**: Verify that `.env`, `.git_backup/`, and browser profiles remain strictly ignored by Git.

## 3. Architecture & Codebase Overview
This project continuously collects, diffs, and catalogs software vulnerabilities and their associated code patches across major open-source projects.

### Pipeline Execution Sequence (`src/`):
1. `collect_vulnerabilities.py`: Scrapes CVE Details using `undetected-chromedriver` (Selenium) to handle Cloudflare protection and SecurityScorecard OAuth login.
2. `diff_CVE_automatization.py`: Daily differential engine separating CVEs into New, Updated, Deleted, and Equal.
3. `find_affected_files.py`: Resolves commit hashes from bug trackers/advisories and extracts affected C/C++ source files via Clang.
4. `create_file_timeline.py`: Builds a topological timeline of commits and modified files.
5. `fix_neutral_code_unit_status_in_affected_files_and_file_timeline.py`: Corrects status tagging across commits.
6. `insert_new_vulnerabilities_in_database.py`: Inserts brand-new CVEs into MySQL.
7. `update_vulnerabilities_in_database.py`: Updates existing CVEs and logs audit trail into `HISTORY` table.
8. `insert_deleted_vulnerabilities_info_in_database.py`: Logs disappearing/disassociated CVEs.
9. `insert_patches_in_database.py`: Links affected commit patches to vulnerabilities in MySQL.

## 4. Git Guidelines
* Root-level PDFs (`Bolsa.pdf`, `Dissertation.pdf`) reside outside the Git repo and should not be tracked.
* Repository-internal documentation PDFs like `Pipeline_Restoration_Report.pdf` are explicitly ignored in `.gitignore`.
