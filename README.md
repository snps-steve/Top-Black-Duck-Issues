Top Black Duck Issues
Overview
This repository contains a Python script designed to extract and analyze vulnerabilities from Black Duck data. The script fetches information about vulnerable components, identifies vulnerabilities based on the CWE Top 25 and OWASP Top 10 lists, and outputs relevant details.

Features
Fetch Vulnerabilities: Retrieves vulnerable components from a specified Black Duck project and version.
Match Vulnerabilities: Compares vulnerabilities against the CWE Top 25 and OWASP Top 10 lists.
Detailed Output: Provides a detailed output of vulnerabilities, including component name, version, severity, and more.
Prerequisites
Python 3.x
Required Python packages (to be listed in requirements.txt)
Installation
Clone this repository:

bash
Copy code
git clone https://github.com/your-username/Top-Black-Duck-Issues.git
Navigate to the project directory:

bash
Copy code
cd Top-Black-Duck-Issues
Install the required Python packages:

bash
Copy code
pip install -r requirements.txt
Usage
Set up your environment variables in a .env file or modify the script directly.

Run the script:

bash
Copy code
python top_black_duck_issues.py
Configuration
The script requires configuration for BASEURL and API_TOKEN. These can be set up in a .env file or directly within the script.

Example
If a .env file is detected, the script will prompt you to accept or modify the project name, version name, BASEURL, and API_TOKEN.

License
This project is licensed under the MIT License. See the LICENSE file for details.

Contributing
If you would like to contribute to this project, please fork the repository and submit a pull request.

Contact
For any questions or issues, please ssmith@blackduck.com.
