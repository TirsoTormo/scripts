#!/usr/bin/env python3
import json
import urllib.request
import urllib.error
import time
import os

# --- GATEWAY CONSTANTS ---
GATEWAY_URL = "http://localhost:8000/webhook"
DEFAULT_TOKEN = "mi_token_secreto_super_seguro"

# Try to parse real configured token from local .env file for convenience
if os.path.exists(".env"):
    try:
        with open(".env", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("GATEWAY_TOKEN="):
                    DEFAULT_TOKEN = line.split("=")[1].strip()
                    break
    except Exception:
        pass

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def dispatch_post(url, payload, headers=None):
    if headers is None:
        headers = {
            'Content-Type': 'application/json',
            'X-Gateway-Token': payload.get("token", "")
        }
        
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode('utf-8'),
        headers=headers
    )
    
    try:
        start_time = time.time()
        with urllib.request.urlopen(req) as response:
            status_code = response.getcode()
            res_data = json.loads(response.read().decode('utf-8'))
            elapsed = (time.time() - start_time) * 1000
            
            print(f"\n\033[92m✔ DISPATCH SUCCESSFUL (Status {status_code}) [{elapsed:.1f}ms]\033[0m")
            print(f"Server Response:\n{json.dumps(res_data, indent=2, ensure_ascii=False)}")
    except urllib.error.HTTPError as e:
        print(f"\n\033[91m✖ HTTP ERROR RETURNED BY GATEWAY (Status {e.code})\033[0m")
        try:
            err_data = json.loads(e.read().decode('utf-8'))
            print(f"Error Detail:\n{json.dumps(err_data, indent=2, ensure_ascii=False)}")
        except Exception:
            print(e.reason)
    except urllib.error.URLError as e:
        print(f"\n\033[91m✖ CONNECTION FAILURE: Is the FastAPI server running on port 8000?\033[0m")
        print(f"Detail: {e.reason}")

def run_menu():
    while True:
        clear_console()
        print("\033[93m======================================================================")
        print(" 🛡️  INTERACTIVE CONTAINER HEALING ALERT SIMULATOR (CLI TOOL)")
        print("======================================================================\033[0m")
        print("Simulate real orchestrator failures. Parameterize client headers & data.")
        print("----------------------------------------------------------------------")
        print(" 1. Dispatch \033[94mINFO\033[0m Event (Logged locally, queued silently in digest)")
        print(" 2. Dispatch \033[93mWARNING\033[0m Event (Buffered in periodic digest summary)")
        print(" 3. Dispatch \033[91mCRITICAL\033[0m on 'docker-postgres' (Triggers Docker restart)")
        print(" 4. Dispatch \033[91mCRITICAL\033[0m on 'k8s-pod-failure' (Triggers Kubernetes pod delete)")
        print(" 5. CREATE \033[95mCUSTOM ENRICHED CONTAINER ALERT\033[0m (Namespaces, containers, actions)")
        print(" 6. Query Server Live Statistics & SQLite Metrics")
        print(" 7. Exit")
        print("----------------------------------------------------------------------")
        
        choice = input("Enter selection [1-7]: ").strip()
        
        if choice == "1":
            payload = {
                "token": DEFAULT_TOKEN,
                "source": "k8s-local-cluster",
                "service": "cron-backup",
                "severity": "INFO",
                "message": "Routine database file dump completed successfully in 14.8 seconds.",
                "timestamp": int(time.time()),
                "metadata": {
                    "platform": "kubernetes",
                    "k8s_namespace": "default"
                }
            }
            dispatch_post(GATEWAY_URL, payload)
            input("\nPress [Enter] to continue...")
            
        elif choice == "2":
            payload = {
                "token": DEFAULT_TOKEN,
                "source": "local-docker",
                "service": "disk-monitor",
                "severity": "WARNING",
                "message": "Storage capacity on volume /var/lib/docker exceeded 85% occupancy threshold.",
                "timestamp": int(time.time()),
                "metadata": {
                    "platform": "docker"
                }
            }
            dispatch_post(GATEWAY_URL, payload)
            input("\nPress [Enter] to continue...")
            
        elif choice == "3":
            payload = {
                "token": DEFAULT_TOKEN,
                "source": "local-docker",
                "service": "docker-postgres",
                "severity": "CRITICAL",
                "message": "Postgres database container reported out-of-memory fatal crashes.",
                "timestamp": int(time.time()),
                "metadata": {
                    "platform": "docker",
                    "docker_container": "postgres",
                    "failing_streak": 4,
                    "logs": "2026-05-19 08:42:02 [error] OOM Killer terminated postgres process"
                }
            }
            dispatch_post(GATEWAY_URL, payload)
            input("\nPress [Enter] to continue...")
            
        elif choice == "4":
            payload = {
                "token": DEFAULT_TOKEN,
                "source": "k8s-local-cluster",
                "service": "k8s-pod-failure",
                "severity": "CRITICAL",
                "message": "Microservice pod status reports CrashLoopBackOff",
                "timestamp": int(time.time()),
                "metadata": {
                    "platform": "kubernetes",
                    "k8s_namespace": "default",
                    "k8s_pod": "postgres-db-prod-abcde",
                    "failing_streak": 3
                }
            }
            dispatch_post(GATEWAY_URL, payload)
            input("\nPress [Enter] to continue...")
            
        elif choice == "5":
            clear_console()
            print("\033[95m======================================================================")
            print(" 🔧 DYNAMIC CUSTOM ALERT BUILDER")
            print("======================================================================\033[0m")
            
            # Read core values
            source = input("1. Source Cluster / Alias (e.g., k8s-prod-cluster): ").strip() or "local-docker"
            service = input("2. Affected Service / Process Name: ").strip() or "docker-postgres"
            
            print("\nSelect Severity: 1=INFO, 2=WARNING, 3=CRITICAL")
            sev_opt = input("3. Level [1-3]: ").strip()
            severity = "CRITICAL"
            if sev_opt == "1": severity = "INFO"
            elif sev_opt == "2": severity = "WARNING"
            
            message = input("4. Event Alert Message: ").strip() or "Manually constructed test event"
            
            # Build flexible telemetry metadata overrides
            metadata = {}
            print("\n--- CONTAINER PLATFORM ROUTING PARAMETERS ---")
            
            platform_choice = input("Choose platform (1=Kubernetes, 2=Docker, 3=None): ").strip()
            if platform_choice == "1":
                metadata["platform"] = "kubernetes"
                metadata["k8s_namespace"] = input("  Namespace (default: default): ").strip() or "default"
                pod_name = input("  Pod name (Optional, for delete action): ").strip()
                if pod_name:
                    metadata["k8s_pod"] = pod_name
                deployment_name = input("  Deployment name (Optional, for rollout restart): ").strip()
                if deployment_name:
                    metadata["k8s_deployment"] = deployment_name
            elif platform_choice == "2":
                metadata["platform"] = "docker"
                metadata["docker_container"] = input("  Container name to target: ").strip() or "postgres"
            
            wants_logs = input("\nDo you want to attach diagnostic logs to this event? (y/n): ").strip().lower()
            if wants_logs == "y":
                metadata["logs"] = input("  Enter log text: ").strip()
            
            # Construct standard payload dictionary
            payload = {
                "token": DEFAULT_TOKEN,
                "source": source,
                "service": service,
                "severity": severity,
                "message": message,
                "timestamp": int(time.time())
            }
            
            if metadata:
                payload["metadata"] = metadata
                
            print("\nConstructed Payload Draft:")
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            
            # Dispatch using payload
            dispatch_post(GATEWAY_URL, payload)
            input("\nPress [Enter] to continue...")
            
        elif choice == "6":
            print("\nQuerying server stats via authenticated GET /stats endpoint...")
            req = urllib.request.Request(
                "http://localhost:8000/stats",
                headers={
                    'Content-Type': 'application/json',
                    'X-Gateway-Token': DEFAULT_TOKEN
                }
            )
            try:
                start_time = time.time()
                with urllib.request.urlopen(req) as response:
                    status_code = response.getcode()
                    res_data = json.loads(response.read().decode('utf-8'))
                    elapsed = (time.time() - start_time) * 1000
                    print(f"\033[92m✔ STATS RETRIEVED SUCCESSFULLY (Status {status_code}) [{elapsed:.1f}ms]\033[0m")
                    print(json.dumps(res_data, indent=2, ensure_ascii=False))
            except urllib.error.HTTPError as e:
                print(f"\033[91m✖ ACCESS DENIED (Status {e.code})\033[0m")
                try:
                    print(json.loads(e.read().decode('utf-8')))
                except Exception:
                    print(e.reason)
            except Exception as e:
                print(f"\033[91m✖ Connection failure trying to query stats: {e}\033[0m")
            input("\nPress [Enter] to continue...")

        elif choice == "7":
            print("\nExiting. Thank you for testing the Webhook Gateway!")
            break
        else:
            print("\n\033[91mInvalid selection. Please choose a menu option [1-7].\033[0m")
            time.sleep(1)

if __name__ == "__main__":
    run_menu()
