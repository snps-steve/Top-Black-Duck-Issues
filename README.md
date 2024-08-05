# Vulnerability Extraction Script

## Overview

This Python script extracts and processes vulnerability information from a specified endpoint. It identifies vulnerabilities related to software components and matches them against known vulnerability lists, such as the Top 25 CWEs and OWASP Top 10. The script provides options to set or confirm project details and API configuration from an `.env` file.

## Features

- Extracts vulnerabilities from the API.
- Matches vulnerabilities against Top 25 CWEs 2023 and OWASP Top 10 2021.
- Displays matched vulnerabilities with color-coded warnings.
- Allows user to input or confirm project and API details.

## Requirements

- Python 3.x
- Requests library

You can install the required Python package using pip:

```bash
pip install requests
Usage
Prepare Configuration

Ensure you have a .env file in the same directory with the following variables:

BASEURL=<Your API Base URL>
API_TOKEN=<Your API Token>
Run the Script

Execute the script using Python:

python script_name.py
If a .env file is detected, you will be prompted to confirm or enter the project name, version name, base URL, and API token.

View Results

The script outputs the identified vulnerabilities, showing details including component name, version, and matches to known vulnerability lists in color-coded text.

Functions
extract_cwe_id(cwe_id)
Extracts the numeric part from a CWE ID string.

get_match_info(cwe_id)
Returns match information for a given CWE ID, including Top 25 CWEs 2023 and OWASP Top 10 2021.

extract_vulnerabilities(vulnerable_components)
Extracts and processes vulnerability information from the API response.

Example Output:

2024-08-05 09:42:32,418 - INFO - Identified Vulnerabilities:
[{
  'componentName': 'apache/xerces-c',
  'componentVersionName': '3.1.1',
  'cweId': 'CWE-119',
  'match': '\033[0;37;93mTop 25 CWEs 2023: Match: 119: Improper Restriction of Operations within the Bounds of a Memory Buffer\033[0;37;0m',
  'description': 'Stack-based buffer overflow in Apache Xerces-C++ before 3.1.4...',
  'name': 'CVE-2016-4463',
  'severity': 'HIGH'
}]

License
This project is licensed under the MIT License - see the LICENSE file for details.

Contributing
Feel free to submit issues or pull requests. For major changes, please open an issue first to discuss what you would like to change.




