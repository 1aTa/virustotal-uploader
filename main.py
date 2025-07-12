import requests
import webbrowser
import os
import hashlib
import argparse
import time
import tkinter as tk
from tkinter import ttk
import threading

def main(file_path):
    api_key = "<your_api_key>"  # your api key here

    headers = {"accept": "application/json", "x-apikey": api_key}

    def sha256_file():
        with open(file_path, 'rb') as file:
            content = file.read()
            if not content:
                exit(1)
            return hashlib.sha256(content).hexdigest()

    def is_size_greater_than_32mb():
        size_bytes = os.path.getsize(file_path)
        if size_bytes == 0:
            exit(1)
        return size_bytes > 33_554_432

    def check_if_file_exists(sha):
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/files/{sha}", headers=headers)
            response.raise_for_status()
            return 'error' not in response.json()
        except requests.RequestException:
            return False

    def get_upload_url():
        try:
            response = requests.get("https://www.virustotal.com/api/v3/files/upload_url", headers=headers)
            response.raise_for_status()
            return response.json()['data']
        except requests.RequestException:
            return None

    def show_progress_popup():
        root = tk.Tk()
        root.title("VirusTotal Uploader")
        root.geometry("300x75")
        root.resizable(False, False)
        style = ttk.Style()
        style.theme_create("dark", parent="clam", settings={
            "TLabel": {"configure": {"background": "#1e1e1e", "foreground": "#ffffff", "font": ("Arial", 11)}},
            "TFrame": {"configure": {"background": "#1e1e1e"}}
        })
        style.theme_use("dark")
        root.configure(bg="#1e1e1e")
        root.eval('tk::PlaceWindow . center')
        frame = ttk.Frame(root)
        frame.pack(anchor="center")
        label = ttk.Label(frame, text="Uploading file to VirusTotal...")
        label.pack(pady=10)
        spinner_label = ttk.Label(frame, text="|")
        spinner_label.pack(pady=0)
        spinner_chars = ['|', '/', '-', '\\']
        spinner_index = [0]
        stop_spinner = [False]
        def update_spinner():
            if not stop_spinner[0] and root.winfo_exists():
                spinner_label.config(text=spinner_chars[spinner_index[0] % 4])
                spinner_index[0] += 1
                root.after(100, update_spinner)
        root.after(0, update_spinner)
        root.update_idletasks()
        return root, lambda: stop_spinner.__setitem__(0, True)

    if not os.path.isfile(file_path):
        exit(1)

    try:
        use_large_upload = is_size_greater_than_32mb()
        sha = sha256_file()
    except:
        exit(1)

    if check_if_file_exists(sha):
        webbrowser.open(f"https://www.virustotal.com/gui/file/{sha}")
        exit()

    upload_url = get_upload_url() if use_large_upload else "https://www.virustotal.com/api/v3/files"
    if not upload_url:
        exit(1)

    root, stop_spinner = show_progress_popup()
    upload_exception = [None]
    file_registered = [False]
    def upload_file():
        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f, "application/octet-stream")}
                response = requests.post(upload_url, files=files, headers=headers)
                response.raise_for_status()
            for _ in range(120):
                if check_if_file_exists(sha):
                    file_registered[0] = True
                    break
                time.sleep(5)
        except (requests.RequestException, IOError) as e:
            upload_exception[0] = e

    upload_thread = threading.Thread(target=upload_file)
    upload_thread.daemon = True
    upload_thread.start()

    while upload_thread.is_alive():
        root.update()
        time.sleep(0.01)

    if upload_exception[0] or not file_registered[0]:
        stop_spinner()
        root.destroy()
        exit(1)

    stop_spinner()
    root.destroy()
    webbrowser.open(f"https://www.virustotal.com/gui/file/{sha}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Submit a file to VirusTotal")
    parser.add_argument("-file", dest="file_path", required=True)
    args = parser.parse_args()
    main(args.file_path)
