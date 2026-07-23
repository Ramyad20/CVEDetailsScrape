# Scraping CVEDetails Repository

This group of scripts follows a pipeline that starts with the scrapping of the website [CveDetails](https://www.cvedetails.com) and finishes with the insertion of the database of all the data.

## Repository Structure

The repository is structured as follows:

- **/src**: All the scripts
  - **/emails**: Module that allows to send notifications to email
  - **/modules**: Module with function that allows to work with the database and with all the vulnerabilities for each project
  - **collect_vulnerabilities**: Download all the CVES information from the website
  - **diff_CVE_automatization.py**: Find two consecutive days of the collection mechanism and find the differences between them
  - **find_affected_files.py**: Find the files of each project that contain the vulnerable code
  - **create_file_timeline.py**: Build a timeline with all the files
  - **fix_neutral_code_unit_status_in_affected_files_and_file_timeline.py**: Fix a bug in the output of the last two scripts
  - **insert_new_vulnerabilities_in_database.py**: Insert new vulnerabilities in the database
  - **update_vulnerabilities_in_database.py**: Insert the updates in the database
  - **insert_deleted_vulnerabilities_info_in_database.py**: Insert information on vulnerabilities that disappear
  - **insert_patches_in_database.py**: Insert the patches from new and updated CVES in the database

## How to Use
To use the scripts it is necessary to configure all the basic information in the following files:
1- */src/emails/config/config.json*
2- */src/modules/config/dynamic_config_template.json*
3- */src/modules/config/static_config.json* 
These files have the paths for each repository, the IDs of each project on the website, the information for connecting to the database, and the information needed for sending the notification, etc.

## Pipeline Restoration & Maintenance Guide

To ensure the pipeline functions reliably against CVEDetails anti-bot protection and authentication updates, several enhancements and fixes have been integrated into this fork.

### Overview of Recent Improvements & Fixes
* **Scraper Modernization & Anti-Detection (`src/modules/scraping.py`)**:
  * Integrated `undetected-chromedriver` to bypass automated bot detection and Cloudflare protection on CVEDetails.
  * Added **Session Health Checks**: Automatically detects crashed or closed browser sessions and re-initializes them cleanly without crashing execution.
  * Implemented **Persistent Chrome Profiles**: Chrome session data and cookies are retained in local profile storage (`src/modules/data/chrome_profile`) to reduce redundant logins and re-verifications.
  * **Dynamic OAuth & SSO Login Flow**: Replaced rigid hardcoded login URLs with dynamic element lookup for SecurityScorecard OAuth login (detects agreement checkboxes, sign-in triggers, and credential inputs automatically).
  * **Interactive Fallback for Cloudflare / CAPTCHA**: If Cloudflare presents a verification prompt or captcha, the scraper gracefully pauses up to 120 seconds for manual user interaction before continuing automatically.
* **Environment & Security Management**:
  * Created `.env.example` to separate sensitive credentials (database passwords, email SMTP tokens, user logins) from tracked repository code.
  * Added `python-dotenv` dependency to `src/requirements.txt`.
  * Updated `.gitignore` to prevent committing sensitive secrets (`.env`), temporary browser profiles (`chrome_profile`), and log outputs.
* **Email & Utility Upgrades**:
  * Updated email notification script (`src/emails/send_email.py`) and config schemas for reliable pipeline alert dispatches.

---

### Step-by-Step Pipeline Setup & Execution

#### 1. Install Dependencies
Ensure Python 3.9+ and Chrome browser are installed on your environment, then install Python requirements:
```bash
pip install -r src/requirements.txt
```

#### 2. Configure Environment Variables & Configs
Copy the sample environment file and update credentials:
```bash
cp .env.example .env
```
Update configuration JSON files with target project settings and database connections:
* `src/emails/config/config.json`
* `src/modules/config/dynamic_config_template.json`
* `src/modules/config/static_config.json`

#### 3. Pipeline Execution Sequence
Run the pipeline scripts in the following order:
1. `python src/collect_vulnerabilities.py`
2. `python src/diff_CVE_automatization.py`
3. `python src/find_affected_files.py`
4. `python src/create_file_timeline.py`
5. `python src/fix_neutral_code_unit_status_in_affected_files_and_file_timeline.py`
6. `python src/insert_new_vulnerabilities_in_database.py`
7. `python src/update_vulnerabilities_in_database.py`
8. `python src/insert_deleted_vulnerabilities_info_in_database.py`
9. `python src/insert_patches_in_database.py`

#### 4. Handling Cloudflare & Manual Login Prompts
When running `collect_vulnerabilities.py`:
* The scraper will open a browser window. If CVEDetails prompts a Cloudflare challenge ("Just a moment..."), click the checkbox in the opened browser window.
* The script will detect resolution automatically and resume execution.

## Additional notes 

  
After every configuration, the next order must be followed:
1- **collect_vulnerabilities**
2- **diff_CVE_automatization.py**
3- **find_affected_files.py**
4- **create_file_timeline.py**
5- **fix_neutral_code_unit_status_in_affected_files_and_file_timeline.py**
6- **insert_new_vulnerabilities_in_database.py**
7- **update_vulnerabilities_in_database.py**
8- **insert_deleted_vulnerabilities_info_in_database.py**
9- **insert_patches_in_database.py**

## Contact

For any questions, suggestions, or issues related to this repository, feel free to contact us through the following means:

- Email: [joao.rafael.henriques@gmail.com](mailto:joao.rafael.henriques@gmail.com)
