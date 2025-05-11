import os
import whois
import platform
import pandas as pd
import requests
import socket
from threading import Thread
import nmap
from ipwhois import IPWhois
import subprocess
import pyshark 
import signal
import sys
import time 
from collections import deque
import shutil  # Import shutil for copying files
import threading
import csv
import matplotlib.pyplot as plt
from flask import Flask, jsonify  # Import Flask for web application

urls = input("Enter your domain or IP address to begin")

domain_list = [value.strip() for value in urls.split(',')]
ip_list = []

def get_local_os_info():
	#os of scanning machine
	os_name = platform.system()
	os_version= platform.version()
	os_release = platform.release()
	os = f"Local OS: {os_name}, Version: {os_version}, Release: {os_release}"
	return os



def scan_target(ip):
	nm = nmap.PortScanner()  # Create Nmap scanner object
	nm.scan(hosts=ip, arguments="-sV")  # Run service detection scan
	cve_items = []
	print(f"Scanning {ip}...\n")
	
	# Iterate through scanned results
	for proto in nm[ip].all_protocols():
		ports = nm[ip][proto].keys()
		for port in sorted(ports):
			service = nm[ip][proto][port].get('name', 'Unknown')
			product = nm[ip][proto][port].get('product', '')
			version = nm[ip][proto][port].get('version', '')
			item = product + " " + version  
			cve_items.append(item) 
		

			print(f"Port: {port}, Service: {service}, Product: {product} {version}")
	return cve_items
	
#Vulnerability Assessment
#NVD API for CVE data

total_high = 0
total_critical = 0

def get_vulnerabilities(service_name):
	url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={str(service_name)}"
	headers = {"User-Agent": "Mozilla/5.0"}  # Prevents blocking

	response = requests.get(url, headers=headers)

	if response.status_code != 200:
		print(f"Error: {response.status_code}")
		return None

	try:
		data = response.json()
	except requests.exceptions.JSONDecodeError:
		print("Error: Received non-JSON response.")
		return None

	cve_list = data.get("vulnerabilities", [])

	if not cve_list:
		print(f"No vulnerabilities found for {service_name}")
		return []

	formatted_cves = []
	high = 0
	critical = 0
	for entry in cve_list:
		cve = entry.get("cve", {})
		cve_id = cve.get("id", "N/A")
		description = next((desc["value"] for desc in cve.get("descriptions", []) if desc["lang"] == "en"), "No description available")
		severity = "N/A"

		# Extract CVSS v3 severity if available
		if "metrics" in cve:
			cvss_v3 = cve["metrics"].get("cvssMetricV30", [])
		if cvss_v3:
			severity = cvss_v3[0]["cvssData"].get("baseSeverity", "N/A")
		elif "cvssMetricV2" in cve["metrics"] and cve["metrics"]["cvssMetricV2"]:
					severity = cve["metrics"]["cvssMetricV2"][0]["baseSeverity"]
	

		# Only store HIGH or CRITICAL severity vulnerabilities
		if severity in ["HIGH", "CRITICAL"]:
			formatted_cves.append(f"**{cve_id}**\nSeverity: {severity}\nDescription: {description}\n")
			if severity == "HIGH":
				high+= 1
			elif severity == "CRITICAL":
				critical+=1
		#formatted_cves.append(f"**{cve_id}**\nSeverity: {severity}\nDescription: {description}\n")
		
	total_high += high
	total_critical += critical
	print(f"High: {high}, Critical: {critical}")
	print(f"Total: {high + critical}")
	return "\n".join(formatted_cves) if formatted_cves else f"No HIGH or CRITICAL vulnerabilities found for {service_name}."



def getWhoIs(domain_list):
	w = ""
	for domain in domain_list:


	#Perform WHOIS domain lookup

		w += f"Results for domain: {domain}\n"
		result = whois.whois(domain)

		org_name = result.get("org", "Not available")
		creation_date = result.get("creation_date", "Not available")
		emails = result.get("emails", "Not available")

		w += f"Organization Name: {org_name}\n"
		w += f"Creation Date: {creation_date}\n"
		w += f"Email(s): {emails}\n"
		w += "\n"



	#Host Discovery

		try:
		
			ip = socket.gethostbyname(domain)
			
			w += (f"IP: IP address for {domain}: {ip}\n")
			w += (f"The domain '{domain}' resolves to IP address: {ip}")
			w += (f"This host is live")
			ip_list.append(ip)
		except socket.gaierror:
			w += f"IP: The domain {domain} does not resolve to an ip.\n"
			ip_list.append("Ip address not found")

	print(w)
	return w


#Port Scanning

	

print("Retrieving port data...")


print("Retrieving port services data...")
	

full_scan = scan_target(ip_list)
	

os_name = get_local_os_info()
print(os_name)


#Vulnerability Assessment


#Snort persistent scanning and alerting

SNORT_PATH = r"C:\Snort\bin\snort.exe"
CONFIG_PATH = r"C:\Snort\etc\snort.conf"
INTERFACE = "5"  
LOG_DIR = r"C:\Users\Hgrant\Desktop\security_scan - Copy"
ALERT_FILE = os.path.join(LOG_DIR, "alert.fast")

def start_snort():
    cmd = [
        SNORT_PATH,
        "-i", INTERFACE,
        "-c", CONFIG_PATH,
        "-A", "fast",          # Output format
        "-l", LOG_DIR,         # Log directory
        "-q"                   # Quiet mode
    ]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def monitor_alert_file():
    print("Monitoring Snort alerts...")
    previous_content = ""  # Variable to store the previous content of the file

    while True:
        try:
            if os.path.exists(ALERT_FILE):
                # Lock the file for writing while checking its content
                with threading.Lock():
                    with open(ALERT_FILE, "r") as f:
                        current_content = f.read()

                # Check if the file is not empty
                if current_content.strip():
                    print("File found.")
                    
                    # Compare the current content with the previous content
                    if current_content != previous_content:
                        print("New content detected in alert file.")
                        previous_content = current_content  # Update the stored content
                else:
                    print("Alert file is empty. No new alerts.")
            else:
                print("Alert file does not exist. Waiting...")
        except Exception as e:
            print(f"Error while monitoring alert file: {e}")

        time.sleep(5)  # Check the file every 5 seconds

def launch_ids(scan_summary, domain_list, ip_list, os_name):
    print("Launching IDS...")
    snort_proc = start_snort()
    print("Snort started. Monitoring traffic...")

    try:
        monitor_thread = Thread(target=monitor_alert_file, daemon=True)
        monitor_thread.start()

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Snort...")
        snort_proc.terminate()
        snort_proc.wait()
        print("Snort stopped.")

    # Append IDS results to the scan summary
    scan_summary.append({
        "domain": domain_list,
        "ip": ip_list,
        "os": os_name,
    })

    save_to_csv(scan_summary)
    return "IDS launched and monitoring completed."

# File monitoring function
def monitor_file(file_path):
	x = ""  # Variable to store the full contents of the file
	last_size = 0  # Tracks the last known size of the file
	temp_file_path = file_path + ".tmp"  # Temporary file path

	print(f"Monitoring file: {file_path}")
	while True:
		try:
			# Check if the file exists
			if os.path.exists(file_path):
				try:
					# Create a temporary copy of the file
					shutil.copy(file_path, temp_file_path)

					current_size = os.path.getsize(temp_file_path)

					# If the file has grown, read the new content
					if current_size > last_size:
						with open(temp_file_path, "r") as file:
							file.seek(last_size)  # Move to the last known position
							y = file.read()  # Read the newly written portion
							print(f"New content detected:\n{y}")
							x += y  # Append the new content to the full content variable

						last_size = current_size  # Update the last known size
				except (OSError, IOError) as e:
					print(f"File access error: {e}. Retrying...")
				finally:
					# Clean up the temporary file
					if os.path.exists(temp_file_path):
						os.remove(temp_file_path)
			else:
				print(f"File '{file_path}' does not exist. Waiting...")
		except Exception as e:
			print(f"Error: {e}")

		time.sleep(1)  # Check for changes every second


#Wireshark periodic scans and text doc reports

#CSV Function

# Save results
def save_to_csv(scan_summary, filename="scan_results.csv"):
	# Dynamically determine the root folder of the script
	root_folder = os.path.dirname(os.path.abspath(__file__))  # Get the directory of the current script
	file_path = os.path.join(root_folder, filename)  # Construct the full path to save the file in the script's directory

	keys = ["domain", "ip", "high", "critical", "os", "whois", "Nmap_info", "No. of Vulnerabilities", "Vulnerabilities"]
	with open(file_path, mode='w', newline='') as file:
		writer = csv.DictWriter(file, fieldnames=keys)
		writer.writeheader()
		for row in scan_summary:
			writer.writerow(row)
	print(f"\nScan results saved to {file_path}")
	return scan_summary
		
#Reporting functionalities
scan_summary = []


def perform_reconnaissance(domain_list, ip_list, scan_summary):
    print("Performing reconnaissance...")
    scan = getWhoIs(domain_list)
    os_name = get_local_os_info()

    scan_summary.append({
        "domain": domain_list,
        "ip": ip_list,
        "os": os_name,
        "whois": scan,
    })

    save_to_csv(scan_summary)
    return "Reconnaissance completed and results saved."


def perform_network_scan(ip_list, full_scan, scan_summary):
    print("Performing network scan...")
    scan_summary.append({
        "ip": ip_list,
        "Nmap_info": full_scan,
    })
    save_to_csv(scan_summary)
    return "Network scan completed and results saved."


#Perform Reconnaissance
print("Performing reconnaissance...")
perform_reconnaissance(domain_list, ip_list, scan_summary)

#Network scan
print("Performing network scan...")
perform_network_scan(ip_list, full_scan, scan_summary)

scan_summary.append({
		"domain": domain_list,
		"ip": ip_list,
		"os": os_name   ,
})
		
save_to_csv(scan_summary)


def comprehensive_scan(domain_list, ip_list, scan_summary):
    print("Performing comprehensive scan...")
    scan = getWhoIs(domain_list)
    full_scan = [scan_target(ip) for ip in ip_list]  # Iterate through ip_list in one line
    os_name = get_local_os_info()
    vulnerabilities = []
    full_scan.append(os_name)

    for service in full_scan:
        vulns = get_vulnerabilities(str(service))
        vulnerabilities.append(vulns)

    scan_summary.append({
        "domain": domain_list,
        "ip": ip_list,
        "high": total_high,
        "critical": total_critical,
        "os": os_name,
        "whois": scan,
        "Nmap_info": full_scan,
        "No. of Vulnerabilities": len(vulnerabilities),
        "Vulnerabilities": vulnerabilities
    })

    save_to_csv(scan_summary)
    return "Comprehensive scan report generated successfully."


def generate_feedback(total_high, total_critical):
    feedback = {
        "rating": "",
        "message": ""
    }

    total_vulnerabilities = total_high + total_critical

    # Rating
    if total_vulnerabilities == 0:
        feedback["rating"] = "Excellent"
        feedback["message"] = "No vulnerabilities detected. Your system is secure."
    elif total_vulnerabilities <= 5:
        feedback["rating"] = "Good"
        feedback["message"] = "Few vulnerabilities detected. Consider addressing them soon."
    elif total_vulnerabilities <= 15:
        feedback["rating"] = "Fair"
        feedback["message"] = "Moderate vulnerabilities detected. Take action to secure your system."
    else:
        feedback["rating"] = "Poor"
        feedback["message"] = "High number of vulnerabilities detected. Immediate action is required!"

    # if critical vulnerabilities exceed high vulnerabilities
    if total_critical > total_high:
        feedback["rating"] = "Very Poor"
        feedback["message"] += " Critical vulnerabilities outnumber high vulnerabilities, which is a serious concern."

    return feedback


# Generate feedback 
feedback = generate_feedback(total_high, total_critical)
print(f"Rating: {feedback['rating']}")
print(f"Message: {feedback['message']}")


app = Flask(__name__)

#route for Reconnaissance Report
@app.route('/reconnaissance', methods=['GET'])
def reconnaissance_report():
    scan_summary = []
    perform_reconnaissance(domain_list, ip_list, scan_summary)
    return jsonify({
        "message": "Reconnaissance report generated successfully.",
        "data": scan_summary
    })

#route for Network Scan Report
@app.route('/network_scan', methods=['GET'])
def network_scan_report():
    scan_summary = []
    full_scan = [scan_target(ip) for ip in ip_list]
    perform_network_scan(ip_list, full_scan, scan_summary)
    return jsonify({
        "message": "Network scan report generated successfully.",
        "data": scan_summary
    })

#route for Comprehensive Scan Report
@app.route('/comprehensive_scan', methods=['GET'])
def comprehensive_scan_report():
    scan_summary = []
    comprehensive_scan(domain_list, ip_list, scan_summary)
    return jsonify({
        "message": "Comprehensive scan report generated successfully.",
        "data": scan_summary
    })

# Feedback Report
@app.route('/feedback', methods=['GET'])
def feedback_report():
    feedback = generate_feedback(total_high, total_critical)
    return jsonify({
        "message": "Feedback report generated successfully.",
        "rating": feedback["rating"],
        "details": feedback["message"]
    })


if __name__ == '__main__':
    app.run(debug=True)




















