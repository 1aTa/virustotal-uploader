import requests
import webbrowser
import os
import hashlib
import argparse
import time

def main(file_path):
    api_key = "<your_api_key>"  # your api key here 

    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    def sha256_file():
        try:
            with open(file_path, 'rb') as file:
                content = file.read()
                if not content:
                    exit(1)  # Silently exit for empty files
                return hashlib.sha256(content).hexdigest()
        except IOError:
            exit(1)

    def is_size_greater_than_32mb():
        try:
            size_bytes = os.path.getsize(file_path)
            if size_bytes == 0:
                exit(1)  # Silently exit for empty files
            return size_bytes > 33_554_432  # 32MB in bytes
        except OSError:
            exit(1)

    def check_if_file_exists(sha):
        check_link = f"https://www.virustotal.com/api/v3/files/{sha}"
        try:
            response = requests.get(check_link, headers=headers)
            response.raise_for_status()
            return 'error' not in response.json()
        except requests.RequestException:
            return False

    def get_upload_url():
        url = "https://www.virustotal.com/api/v3/files/upload_url"
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()['data']
        except requests.RequestException:
            return None

    # Verify file exists and is readable
    if not os.path.isfile(file_path):
        exit(1)

    # Check file size and calculate hash
    try:
        is_size_greater_than_32mb()  # Check size first
        sha = sha256_file()
    except:
        exit(1)

    # Check if the file already exists on VirusTotal
    if check_if_file_exists(sha):
        webbrowser.open(f"https://www.virustotal.com/gui/file/{sha}")
        exit()

    # Determine upload URL based on file size
    upload_url = get_upload_url() if is_size_greater_than_32mb() else "https://www.virustotal.com/api/v3/files"
    if not upload_url:
        exit(1)

    # Upload the file
    try:
        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f, "application/octet-stream")}
            response = requests.post(upload_url, files=files, headers=headers)
            response.raise_for_status()
    except (requests.RequestException, IOError):
        exit(1)

    # Poll to confirm file is registered
    file_hash = sha
    max_attempts = 3  # Wait up to ~15 seconds (5s * 3)
    attempt = 0
    while attempt < max_attempts:
        if check_if_file_exists(sha):
            break
        time.sleep(5)  # Short delay to allow VT to register the file
        attempt += 1

    # Open the results page
    webbrowser.open(f"https://www.virustotal.com/gui/file/{file_hash}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Submit a file to VirusTotal for analysis")
    parser.add_argument("-file", dest="file_path", help="Path to the file for analysis")
    args = parser.parse_args()

    if args.file_path:
        main(args.file_path)
    else:
        exit(1)
