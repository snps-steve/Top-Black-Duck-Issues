# Vulnerability Extraction Script

## Overview

This repository contains a Python script designed to extract and analyze vulnerabilities from Black Duck data. The script fetches information about vulnerable components, identifies vulnerabilities based on the CWE Top 25 and OWASP Top 10 lists, and outputs relevant details.

The script provides options to set or confirm project details and API configuration from a `.env` file.

## Features

- Fetch Vulnerabilities: Retrieves vulnerable components from a specified Black Duck project and version from the specified Black Duck Server's APIs.
- Match Vulnerabilities: Compares vulnerabilities against the CWE Top 25 and OWASP Top 10 lists.
- Detailed Output: Provides a detailed output of vulnerabilities, including component name, version, severity, and more.

## Requirements

- Python 3.x
- Requests library

You can install the required Python package using pip or let the script install them for you:

```bash
pip install requests python-dotenv
```

## Installation
Clone this repository:

```bash
git clone https://github.com/snps-steve/top-black-duck-issues
```

Navigate to the project directory:

```bash
cd top-black-duck-issues
```

### Usage
Set up your environment variables in a .env file or simply let the script prompt you for the required information. 

Run the script:

```bash
python top.py
```

### Configuration
During the first execution of the script, the user will be prompted for the BASEURL, API_TOKEN, project, and project version. These fields will then be stored in a .env file in the project folder. If a .env file is detected, the script will prompt you to either use the existing BASEURL, API_TOKEN, project, and project version as 'defaults' or you can enter different information.
<br>
Example:
<br>
BASEURL=https://blackduck.synopsys.com<br>
API_TOKEN=[REDACTED]<br>
project_name=testVMDK<br>
version_name=1.0<br>
<br>
### License
This project is licensed under the MIT License.

### Contributing
If you would like to contribute to this project, please fork the repository and submit a pull request.

### Contact
For any questions or issues, please contact Steve Smith (ssmith@blackduck.com).
