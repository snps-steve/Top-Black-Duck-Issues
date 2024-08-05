import os
import sys
import logging
import requests
import subprocess
from dotenv import load_dotenv
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pprint import pprint

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define CWE mappings for Top 25 CWEs 2023 and OWASP Top 10 2021
TOP_25_CWES_2023 = {
    787: "Out-of-bounds Write",
    79: "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    89: "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    416: "Use After Free",
    78: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    20: "Improper Input Validation",
    125: "Out-of-bounds Read",
    22: "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    352: "Cross-Site Request Forgery (CSRF)",
    434: "Unrestricted Upload of File with Dangerous Type",
    862: "Missing Authorization",
    476: "NULL Pointer Dereference",
    287: "Improper Authentication",
    190: "Integer Overflow or Wraparound",
    502: "Deserialization of Untrusted Data",
    77: "Improper Neutralization of Special Elements used in a Command ('Command Injection')",
    119: "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    798: "Use of Hard-coded Credentials",
    918: "Server-Side Request Forgery (SSRF)",
    306: "Missing Authentication for Critical Function",
    362: "Concurrent Execution using SharedResource with Improper Synchronization ('Race Condition')",
    269: "Improper Privilege Management",
    94: "Improper Control of Generation of Code ('Code Injection')",
    863: "Incorrect Authorization",
    276: "Incorrect Default Permissions"
}

OWASP_TOP_10_2021 = {
    1345: "Broken Access Control",
    1346: "Cryptographic Failures",
    1347: "Injection",
    1348: "Insecure Design",
    1349: "Security Misconfiguration",
    1352: "Vulnerable and Outdated Components",
    1353: "Identification and Authentication Failures",
    1354: "Software and Data Integrity Failures",
    1355: "Security Logging and Monitoring Failures",
    1356: "Server-Side Request Forgery (SSRF)"
}

def check_and_install_packages():
    '''Function to check for necessary packages and install them if missing.'''
    try:
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        from dotenv import load_dotenv
    except ImportError:
        missing_packages = []
        try:
            import requests
        except ImportError:
            missing_packages.append('requests')

        try:
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
        except ImportError:
            if 'requests' not in missing_packages:
                missing_packages.append('requests')

        try:
            from dotenv import load_dotenv
        except ImportError:
            missing_packages.append('python-dotenv')

        if missing_packages:
            install = input(f"The following packages are missing: {missing_packages}. Do you want to install them? Yes/no (default is Yes): ").strip().lower()
            if install in ('', 'y', 'yes'):
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
                    import requests
                    from requests.packages.urllib3.exceptions import InsecureRequestWarning
                    from dotenv import load_dotenv
                except subprocess.CalledProcessError as e:
                    logging.error(f"Failed to install packages: {e}")
                    sys.exit()
            elif install in ('n', 'no'):
                logging.info("Installation aborted by the user.")
                sys.exit()
            else:
                logging.info("Invalid input. Installation aborted.")
                sys.exit()

def prompt_with_default(prompt, default):
    '''Prompt the user with a default value.'''
    user_input = input(f"{prompt} (default: {default}): ").strip()
    return user_input if user_input else default

def load_env_variables():
    '''Function to load environment variables from .env file or user input.'''
    if os.path.exists('.env'):
        logging.info("Detected .env file.")
        load_dotenv()
    else:
        logging.info(".env file not detected. You will be prompted to enter environment variables.")

    global BASEURL, API_TOKEN, project_name, version_name

    BASEURL = os.getenv('BASEURL')
    API_TOKEN = os.getenv('API_TOKEN')
    project_name = os.getenv("project_name")
    version_name = os.getenv("version_name")

    if BASEURL and API_TOKEN and project_name and version_name:
        logging.info(f"Loaded BASEURL: {BASEURL}, API_TOKEN: {API_TOKEN}, project name: {project_name}, and version name: {version_name} from .env file.")
        BASEURL = prompt_with_default("Enter BASEURL", BASEURL)
        API_TOKEN = prompt_with_default("Enter API_TOKEN", API_TOKEN)
        project_name = prompt_with_default("Enter your Project Name", project_name)
        version_name = prompt_with_default("Enter your Version Name", version_name)
    else:
        BASEURL = input("Enter BASEURL: ").strip()
        API_TOKEN = input("Enter API_TOKEN: ").strip()
        project_name = input("Enter your Project Name: ").strip()
        version_name = input("Enter your Version Name: ").strip()

    with open('.env', 'w') as f:
        f.write(f"BASEURL={BASEURL}\n")
        f.write(f"API_TOKEN={API_TOKEN}\n")
        f.write(f"project_name={project_name}\n")
        f.write(f"version_name={version_name}\n")

def http_error_check(url, headers, code, response):
    '''Function to check the HTTP status code.'''
    if code == 200:
        return
    if code > 399:
        logging.error(f"Unable to pull info from endpoint. URL: {url}, HTTP error: {code}")
        logging.error(response.text)
        sys.exit()
    else:
        raise Exception("Error while getting data.", code)

def get_url(http_method, url, headers, payload=None):
    '''Function to enumerate data from a URL or API endpoint.'''
    try:
        response = requests.request(http_method, url, headers=headers, data=payload, verify=False, timeout=15)
        code = response.status_code
        http_error_check(url, headers, code, response)
        if code == 200:
            return response.json(), response
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        sys.exit()

def get_auth():
    '''Function to authenticate to the BD API and grab the bearer token and csrf token.'''
    url = f"{BASEURL}/api/tokens/authenticate"
    headers = {
        'Accept': 'application/vnd.blackducksoftware.user-4+json',
        'Authorization': 'token ' + API_TOKEN
    }
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    response_json, response_obj = get_url("POST", url, headers)
    if response_json:
        global bearerToken, csrfToken
        bearerToken = response_json['bearerToken']
        csrfToken = response_obj.headers['X-CSRF-TOKEN']

def get_project_id_by_name(project_name):
    '''Function to get the project ID by project name.'''
    url = f"{BASEURL}/api/projects?q=name:{project_name}"
    headers = {
        "Authorization": "Bearer " + bearerToken,
        "Accept": "application/vnd.blackducksoftware.project-detail-5+json"
    }
    response_json, _ = get_url("GET", url, headers)
    if response_json and 'items' in response_json and len(response_json['items']) > 0:
        return response_json['items'][0]['_meta']['href'].split('/')[-1]
    else:
        logging.error(f"Project with name '{project_name}' not found.")
        sys.exit()

def get_version_id_by_name(project_id, version_name):
    '''Function to get the version ID by version name.'''
    url = f"{BASEURL}/api/projects/{project_id}/versions?q=versionName:{version_name}"
    headers = {
        "Authorization": "Bearer " + bearerToken,
        "Accept": "application/vnd.blackducksoftware.project-detail-5+json"
    }
    response_json, _ = get_url("GET", url, headers)
    if response_json and 'items' in response_json and len(response_json['items']) > 0:
        return response_json['items'][0]['_meta']['href'].split('/')[-1]
    else:
        logging.error(f"Version with name '{version_name}' not found in project ID '{project_id}'.")
        sys.exit()

def get_project_version_details(project_id, version_id):
    '''Function to get the project version details.'''
    url = f"{BASEURL}/api/projects/{project_id}/versions/{version_id}"
    headers = {
        "Authorization": "Bearer " + bearerToken,
        "Accept": "application/vnd.blackducksoftware.project-detail-5+json"
    }
    response_json, _ = get_url("GET", url, headers)
    return response_json

def get_vulnerable_components(project_id, version_id):
    '''Function to get the vulnerable components and their vulnerabilities.'''
    url = f"{BASEURL}/api/projects/{project_id}/versions/{version_id}/vulnerable-bom-components"
    headers = {
        "Authorization": "Bearer " + bearerToken,
        "Accept": "application/vnd.blackducksoftware.bill-of-materials-6+json"
    }
    response_json, _ = get_url("GET", url, headers)
    return response_json

def extract_vulnerabilities_and_print(vulnerable_components):
    '''Function to extract vulnerabilities from vulnerable components and print them directly.'''
    for component in vulnerable_components.get('items', []):
        component_name = component.get('componentName')
        component_version_name = component.get('componentVersionName')
        vulnerability_info = component.get('vulnerabilityWithRemediation', {})
        print_vulnerability_info(component_name, component_version_name, vulnerability_info)

def print_vulnerability_info(component_name, component_version_name, vulnerability_info):
    '''Function to print vulnerability information with proper formatting.'''
    original_cwe_id = vulnerability_info.get('cweId')  # Original CWE ID with "CWE-"
    cwe_id = extract_cwe_id(original_cwe_id)  # Extracted CWE ID for matching
    match_info = get_match_info(cwe_id)
    
    print(f"Component Name: {component_name}")
    print(f"Component Version: {component_version_name}")
    print(f"Vulnerability Name: {vulnerability_info.get('vulnerabilityName')}")
    print(f"Description: {vulnerability_info.get('description')}")
    print(f"Severity: {vulnerability_info.get('severity')}")
    print(f"CWE ID: {original_cwe_id}")  # Display the original CWE ID
    if match_info:
        print(f"\033[93m{match_info}\033[0m")  # Apply yellow color
    print()

def extract_cwe_id(cwe_id):
    '''Helper function to extract CWE ID from string format.'''
    if cwe_id and cwe_id.startswith('CWE-'):
        return int(cwe_id.split('-')[1])
    return None

def get_match_info(cwe_id):
    '''Helper function to get match information for a given CWE ID.'''
    if cwe_id in TOP_25_CWES_2023:
        return f"Top 25 CWEs 2023: Match: CWE-{cwe_id}: {TOP_25_CWES_2023[cwe_id]}"
    if cwe_id in OWASP_TOP_10_2021:
        return f"OWASP Top 10 2021: Match: CWE-{cwe_id}: {OWASP_TOP_10_2021[cwe_id]}"
    return ''

def main():
    check_and_install_packages()
    load_env_variables()
    get_auth()
    project_id = get_project_id_by_name(project_name)
    version_id = get_version_id_by_name(project_id, version_name)
    project_version_details = get_project_version_details(project_id, version_id)
    vulnerable_components = get_vulnerable_components(project_id, version_id)
    extract_vulnerabilities_and_print(vulnerable_components)

if __name__ == "__main__":
    main()
