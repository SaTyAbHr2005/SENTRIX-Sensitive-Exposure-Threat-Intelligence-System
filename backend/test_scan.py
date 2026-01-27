import requests
import time
import sys
import json

BASE_URL = "http://127.0.0.1:5000/api"
TARGET_URL = "https://cake.com"

def start_scan():
    # Debug connection
    try:
        root_resp = requests.get("http://127.0.0.1:5000/api/ui")
        print(f"[*] Root check: {root_resp.status_code} - {root_resp.text}")
    except Exception as e:
        print(f"[-] Root check failed: {e}")

    print(f"[*] Starting scan for {TARGET_URL}...")
    url = f"{BASE_URL}/start_scan"
    print(f"[*] POST {url}")
    try:
        resp = requests.post(url, json={"url": TARGET_URL})
        if resp.status_code == 201:
            data = resp.json()
            task_id = data.get("task_id")
            print(f"[+] Scan started successfully! Task ID: {task_id}")
            return task_id
        else:
            print(f"[-] Failed to start scan. Status: {resp.status_code}")
            print(f"[-] Response: {resp.text[:200]}...") 
            return None
    except Exception as e:
        print(f"[-] Error connecting to API: {e}")
        return None

def poll_status(task_id):
    print("[*] Polling for status...")
    while True:
        try:
            resp = requests.get(f"{BASE_URL}/task_status/{task_id}")
            if resp.status_code == 200:
                data = resp.json()
                status = data.get("status")
                progress = data.get("progress", "N/A")
                
                sys.stdout.write(f"\r[*] Status: {status} | Progress: {progress}   ")
                sys.stdout.flush()
                
                if status in ["finished", "failed", "stopped"]:
                    print("\n")
                    return data
            else:
                print(f"\n[-] Error fetching status: {resp.status_code}")
                
            time.sleep(2)
        except Exception as e:
            print(f"\n[-] Polling error: {e}")
            break

def show_results(task_id):
    print(f"[*] Fetching results for Task ID: {task_id}")
    
    # JS Files
    try:
        js_resp = requests.get(f"{BASE_URL}/js_files/{task_id}")
        if js_resp.status_code == 200:
            js_files = js_resp.json().get("js_files", [])
            print(f"[+] Discovered {len(js_files)} JS files.")
    except:
        print("[-] Failed to fetch JS files")

    # Leaks
    try:
        leaks_resp = requests.get(f"{BASE_URL}/leaks/{task_id}")
        if leaks_resp.status_code == 200:
            leaks = leaks_resp.json().get("leaks", [])
            print(f"[+] Found {len(leaks)} leaks.")
            for leak in leaks:
                print(f"    - {leak.get('severity', 'UNKNOWN')}: {leak.get('description', 'No desc')}")
    except:
        print("[-] Failed to fetch leaks")

    # Endpoints
    try:
        status_resp = requests.get(f"{BASE_URL}/task_status/{task_id}")
        if status_resp.status_code == 200:
            results = status_resp.json().get("results", {})
            endpoints = results.get("endpoints", [])
            print(f"[+] Discovered {len(endpoints)} endpoints.")
            for ep in endpoints[:5]:  # Show first 5
                print(f"    - {ep.get('link')}")
            if len(endpoints) > 5:
                print(f"    ... and {len(endpoints) - 5} more")
    except:
        print("[-] Failed to fetch endpoints")

    # Risk Score
    try:
        status_resp = requests.get(f"{BASE_URL}/task_status/{task_id}")
        if status_resp.status_code == 200:
            risk = status_resp.json().get("results", {}).get("risk_ml", {}).get("score", "N/A")
            print(f"[+] Final Risk Score: {risk}")
    except:
        print("[-] Failed to fetch risk score")

if __name__ == "__main__":
    task_id = start_scan()
    if task_id:
        final_status = poll_status(task_id)
        if final_status and final_status.get("status") == "finished":
            print("[+] Scan completed successfully!")
            show_results(task_id)
        else:
            print(f"[-] Scan ended with status: {final_status.get('status')}")
