__author__ = "Alexios Nersessian"
__copyright__ = "The MIT License (MIT)"
__email__ = "anersess@cisco.com"
__version__ = "v1.0"

import getpass
import threading
import gpt3_tokenizer
import openai
import pandas as pd
import os
import time
import requests
import urllib3
import json
import copy
import sys

"""
    usage: python3 greennetsec.py
"""

urllib3.disable_warnings()

# Create an event to signal when the main function is done
DONE_EVENT = threading.Event()


def loading_bar():
    block = u'\u2588'
    progress = 0
    time.sleep(2)

    while not DONE_EVENT.is_set():
        progress += 1
        print(f"\rAnalysis underway: {block * progress}{' ' * (30 - progress)}", end='')
        sys.stdout.flush()  # Manually flush the output buffer
        if progress == 30:
            progress = 0
        time.sleep(1)

    print()


def cisco_console_api(client_id, client_secret):
    import requests

    url = "https://id.cisco.com/oauth2/default/v1/token"

    payload = f'grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    try:
        response = requests.request("POST", url, headers=headers, data=payload)
        return response.json()["access_token"]

    except Exception as e:
        print(e)


def open_vuln_api(token, os_type, version, score=7):
    cve_info = ""
    cve_counter = 0

    os_types = {"aci": "aci", "IOS": "ios", "IOS-XE": "iosxe", "nxos": "nxos", "asa": "asa", "ftd": "ftd", "fmc": "fmc",
                "fxos": "fxos"}
    url = f"https://apix.cisco.com/security/advisories/v2/OSType/{os_types[os_type]}?version={version}"

    headers = {"Accept": "application/json", 'Authorization': f'Bearer {token}'}

    response = requests.request('GET', url, headers=headers)

    try:
        for cve in response.json().get("advisories"):
            if float(cve["cvssBaseScore"]) >= score:
                cve_counter += 1
                cve_info += f'{cve_counter})    advisoryTitle: ' + cve['advisoryTitle'] + "\n"
                cve_info += '        cvssBaseScore: ' + cve['cvssBaseScore'] + "\n"
                cve_info += '        publicationUrl: ' + cve['publicationUrl'] + "\n\n"
    except:
        cve_info = f"No CVEs found with a score of {score} or higher."

    return cve_info


# DNAC uses basic auth and a short-lived token is used for making API calls
def get_auth_token(base_url, username, password):
    global DONE_EVENT

    try:
        url = f'https://{base_url}/dna/system/api/v1/auth/token'
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

        # Make the POST Request to get a Token
        response = requests.post(url, auth=(username, password), headers=headers, verify=False)

        if response.status_code == 401 or response.status_code == 403:
            print()
            print("Issue with credentials!")
            print()
            return

        # Validate Response
        if 'error' in response.json():
            print()
            print('ERROR: Failed to retrieve Access Token!')
            print(f"REASON: {response.json()['error']}")

        else:
            return response.json()['Token']  # return only the token

    except Exception as e:
        print(e)
        DONE_EVENT.set()  # Signal that the main function is done
        return


def command_runner(base_url, token, command, device_uuid_list):
    global DONE_EVENT
    url = f"https://{base_url}/dna/intent/api/v1/network-device-poller/cli/read-request"
    headers = {"Accept": "application/json", "Content-type": "application/json", "x-auth-token": token}

    body = {
        "commands":
            command
        ,
        "deviceUuids": device_uuid_list
    }

    try:
        response = requests.post(url, headers=headers, json=body, verify=False)
        return response.json()['response']['taskId']

    except Exception as e:
        print(e)
        DONE_EVENT.set()  # Signal that the main function is done


def get_devices_by_type(base_url, token, dev_type=None):
    global DONE_EVENT
    offset = 1
    limit = 500  # Do NOT exceed 500 as the limit (Per DNAC documentation)
    device_list = []

    headers = {
        "content-type": "application/json",
        "Accept": "application/json",
        "x-auth-token": token
    }

    try:
        while True:
            # Make the GET Request
            url = f"https://{base_url}/dna/intent/api/v1/network-device?offset={offset}&limit={limit}"

            if dev_type:
                url = f"https://{base_url}/dna/intent/api/v1/network-device?family={dev_type[0]}={dev_type[1]}&offset={offset}&limit={limit}"

            response = requests.request("GET", url, headers=headers, verify=False)

            if response.json()['response'] and response.status_code != 401:
                device_list.extend(response.json()['response'])
                offset += limit
            else:
                break

        return device_list  # return the list of dnac devices

    except Exception as e:
        print(e)
        DONE_EVENT.set()  # Signal that the main function is done
        return


def download_file(base_url, token, file_id):
    global DONE_EVENT
    url = f"https://{base_url}/dna/intent/api/v1/file/{file_id}"

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "x-auth-token": token,
        "Connection": "keep-alive",
        "Host": "dnac.gma.ciscolabs.com"
    }

    try:
        response = requests.request("GET", url, headers=headers, verify=False)

        return response.json()

    except Exception as e:
        print(e)
        DONE_EVENT.set()  # Signal that the main function is done
        return


def get_task_by_id(base_url, token, task_id):
    global DONE_EVENT
    url = f"https://{base_url}/dna/intent/api/v1/task/{task_id}"

    headers = {
        "content-type": "application/json",
        "Accept": "application/json",
        "x-auth-token": token
    }

    try:
        while True:
            response = requests.request("GET", url, headers=headers, verify=False)
            if 'fileId' not in response.json()["response"]["progress"]:
                time.sleep(1)
            else:
                break

        return json.loads(response.json()["response"]["progress"])[
            'fileId']  # return this "{\"fileId\":\"8181bb48-9fec-4d01-aae5-c1b85fb0bb7a\"}"

    except Exception as e:
        print(e)
        DONE_EVENT.set()  # Signal that the main function is done
        return


def divide_list(lst, chunk_size):
    global DONE_EVENT
    divided_list = []

    try:
        for i in range(0, len(lst), chunk_size):
            divided_list.append(lst[i:i + chunk_size])
        return divided_list

    except Exception as e:
        print(e)
        DONE_EVENT.set()  # Signal that the main function is done
        return


def tokenize_text(text):
    try:
        return gpt3_tokenizer.encode(text)

    except Exception as e:
        print(e)
        DONE_EVENT.set()  # Signal that the main function is done
        return


def detokenize_tokens(tokens):
    global DONE_EVENT
    try:
        return gpt3_tokenizer.decode(tokens)

    except Exception as e:
        print(e)
        DONE_EVENT.set()  # Signal that the main function is done
        return


def split_into_chunks(tokens, max_tokens, overlap):
    global DONE_EVENT
    chunks = []
    start = 0

    try:
        while start < len(tokens):
            end = min(start + max_tokens, len(tokens))
            chunk = tokens[start:end]
            chunks.append(chunk)
            # Move start position ahead by (max_tokens - overlap) to create overlap
            start += max_tokens - overlap

            # If the next chunk would be out of bounds, ensure the last part is included
            if end == len(tokens):
                break

    except Exception as e:
        print(e)
        DONE_EVENT.set()  # Signal that the main function is done

    return chunks


def analyze_output(output):
    global DONE_EVENT
    analysis = None

    prompt = (f"Analyze the following Cisco network device configuration for energy-saving opportunities and potential "
              f"security vulnerabilities. Provide actionable recommendations as bullet points and estimate potential "
              f"energy savings as a percentage:\n{output}")

    try:
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo-0125",  # model="gpt-4o",
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            temperature=0.2,
            # The sampling temperature, between 0 and 1. Higher values like 0.8 will make the output more random, while lower values like 0.2 will make it more focused and deterministic
            # top_p=0.1,
            max_tokens=1000
        )

        analysis = response.choices[0].message.content

    except Exception as e:
        print(e)
        DONE_EVENT.set()  # Signal that the main function is done

    return analysis


def analyze_devices(device_list, token, url, cve_token):
    dev_uuid_list = []
    dev_uuid_to_ip_dict = {}
    software_pid_dict = {}
    chunk_size = 50  # how many devices per API call
    cve_dict = {}

    # Create device uuid list and device uuid to ip dict
    for dev_id in device_list:
        dev_uuid_to_ip_dict[dev_id["id"]] = dev_id["hostname"]
        dev_uuid_list.append(dev_id["id"])

        if cve_token and not cve_dict.get(dev_id["softwareVersion"]):
            cve_dict[dev_id["softwareVersion"]] = open_vuln_api(cve_token, dev_id["softwareType"],
                                                                dev_id["softwareVersion"], score=8)

        software_pid_dict[dev_id["id"]] = [dev_id["softwareType"] + ' ' + dev_id["softwareVersion"], dev_id["type"],
                                           cve_dict.get(dev_id["softwareVersion"]) or "N/A"]

    if len(dev_uuid_list) > chunk_size:
        raw_output = []
        uuid_list_of_lists = divide_list(dev_uuid_list, chunk_size)

        for uuid_group in uuid_list_of_lists:
            task_id = command_runner(url, token, [
                "show interfaces status",
                "show power inline",
                "show environment all",
                "show inventory",
                "show processes cpu",

            ], uuid_group)

            task_run_id = command_runner(url, token, [
                "show ip route",
                "show running-config"
            ], dev_uuid_list)

            time.sleep(7)
            file_id = get_task_by_id(url, token, task_id)
            file_id2 = get_task_by_id(url, token, task_run_id)

            raw_output = download_file(url, token, file_id)
            raw_run_output = download_file(url, token, file_id2)

    else:
        task_id = command_runner(url, token, [
            "show interfaces status",
            "show power inline",
            "show environment all",
            "show inventory",
            "show processes cpu",

        ], dev_uuid_list)

        task_run_id = command_runner(url, token, [
            "show ip route",
            "show running-config"
        ], dev_uuid_list)

        time.sleep(7)
        file_id = get_task_by_id(url, token, task_id)
        file_id2 = get_task_by_id(url, token, task_run_id)

        raw_output = download_file(url, token, file_id)
        raw_run_output = download_file(url, token, file_id2)

    results = []
    output_copy = copy.deepcopy(raw_output)

    for i, dev in enumerate(raw_output):
        version_ouput = software_pid_dict[dev["deviceUuid"]][0]
        pid = software_pid_dict[dev["deviceUuid"]][1]
        cve_urls = software_pid_dict[dev["deviceUuid"]][2]

        if dev.get("commandResponses").get("SUCCESS"):
            # Convert dict to json string
            del output_copy[i]["commandResponses"]["SUCCESS"]["show processes cpu"]
            output_str = json.dumps(output_copy[i].get("commandResponses").get("SUCCESS"), indent=4)

        analysis = analyze_output(output_str)
        potential_savings = extract_potential_savings(analysis)

        cpu_out = dev.get("commandResponses").get("SUCCESS").get("show processes cpu")
        # Tokenize the large text
        cpu_tokens = tokenize_text(cpu_out)

        run_conf_out = raw_run_output[i].get("commandResponses").get("SUCCESS").get("show running-config")
        # Tokenize the large text
        config_tokens = tokenize_text(run_conf_out)

        # Set the maximum token limit
        max_token_limit = 15000
        overlap = 50

        # Split tokens into chunks
        cpu_chunks = split_into_chunks(cpu_tokens, max_token_limit, overlap)
        # Split tokens into chunks
        config_chunks = split_into_chunks(config_tokens, max_token_limit, overlap)

        # Convert chunks back to text
        config_analysis = ""
        config_chunks = [detokenize_tokens(chunk) for chunk in config_chunks]

        # Convert chunks back to text
        cpu_analysis = ""
        cpu_chunks = [detokenize_tokens(chunk) for chunk in cpu_chunks]

        for chunk in cpu_chunks:
            cpu_analysis += analyze_output(chunk)

        for chunk in config_chunks:
            config_analysis += analyze_output(chunk)

        ip_route_out = raw_run_output[i].get("commandResponses").get("SUCCESS").get("show ip route")
        ip_route_analysis = analyze_output(ip_route_out)

        results.append({
            'Hostname': dev_uuid_to_ip_dict[dev['deviceUuid']],
            'General Analysis (interfaces status,power inline,environment all,inventory,processes cpu)': analysis,
            'Running-config Analysis': config_analysis,
            'CPU Analysis': cpu_analysis,
            'Route Table Analysis': ip_route_analysis,
            'Product ID': pid,
            'Code Version': version_ouput,
            'Critical CVEs': cve_urls,
            'Potential Energy Savings (%)': potential_savings
        })

    # Create a DataFrame and write to Excel
    if results:
        df = pd.DataFrame(results)
        df.to_excel('ai_analysis_report.xlsx', index=False)

        print()
        print("Done! Report written to 'ai_analysis_report.xlsx'.")

    print()
    return


def extract_potential_savings(analysis):
    # Use regex to extract the potential savings percentage from the analysis
    import re
    match = re.search(r'(\d+(-\d+)?%)', analysis)

    if match:
        return match.group(1)

    else:
        return 0


def main(username, password, url, cve_token, DONE_EVENT):
    cc_token = get_auth_token(url, username, password)

    # Get Device List according to type eg ["Switches+and+Hubs","Cisco+Catalyst+9300+Switch"]
    # device_list = get_devices_by_type(url, cc_token, ["Switches+and+Hubs","Cisco Catalyst 9000 UADP 8 Port Virtual Switch"])
    device_list = get_devices_by_type(url, cc_token)

    print("Starting analysis..")
    try:
        if device_list:
            analyze_devices(device_list, cc_token, url, cve_token)
        else:
            print("No devices to analyze!")
            DONE_EVENT.set()
            return

    except Exception as e:
        print(e)
        DONE_EVENT.set()  # Signal that the main function is done
        return

    DONE_EVENT.set()  # Signal that the main function is done


def display_welcome_message():
    welcome_message = """
           _____                     _   _      _    _____           
          / ____|                   | \ | |    | |  / ____|          
         | |  __ _ __ ___  ___ _ __ |  \| | ___| |_| (___   ___  ___ 
         | | |_ | '__/ _ \/ _ \ '_ \| . ` |/ _ \ __|\___ \ / _ \/ __|
         | |__| | | |  __/  __/ | | | |\  |  __/ |_ ____) |  __/ (__ 
          \_____|_|  \___|\___|_| |_|_| \_|\___|\__|_____/ \___|\___|

                Green Network Security (GreenNetSec) Analyzer
                ---------------------------------------------

    Analyzing Cisco IOS and IOS XE devices for energy efficiency and security...

    Please wait while we process the configurations and provide recommendations.

    This software is licensed under the MIT License.
    """

    print(welcome_message)
    print()


if __name__ == "__main__":
    display_welcome_message()

    try:
        openai.api_key = os.environ['OPEN_API_KEY']

    except KeyError:
        print("Environment variable 'OPEN_API_KEY' not found!")
        print("Goodbye..")
        exit(0)

    try:
        cve_token = cisco_console_api(os.environ['PSIRT_API_KEY'], os.environ['PSIRT_API_SECRET'])

    except KeyError:
        print("Environment variable 'PSIRT_API_KEY' or 'PSIRT_API_SECRET' not found!")
        cve_token = None


    # CC creds
    cc_url = input("Enter your Catalyst Center URL or IP: ")  # "sandboxdnac.cisco.com"
    cc_username = input("Enter your Catalyst Center username: ")  # "devnetuser"
    cc_password = getpass.getpass()  # "Cisco123!"

    # Create a thread for the progress bar function
    progress_thread = threading.Thread(target=loading_bar)

    # Start the progress bar thread
    progress_thread.start()

    main(cc_username, cc_password, cc_url.replace("https://", ""), cve_token, DONE_EVENT)

    # Wait for the progress bar thread to finish
    progress_thread.join()
