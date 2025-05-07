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





urls = input("Enter your domain or IP address to begin")

domain_list = [value.strip() for value in urls.split(',')]


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
		

	print(f"High: {high}, Critical: {critical}")
	print(f"Total: {high + critical}")
	return "\n".join(formatted_cves) if formatted_cves else f"No HIGH or CRITICAL vulnerabilities found for {service_name}."


for domain in domain_list:


	#Perform WHOIS domain lookup

	print(f"Results for domain: " + domain)
	result = whois.whois(domain)

	org_name = result.get("org", "Not available")
	creation_date = result.get("creation_date", "Not available")
	emails = result.get("emails", "Not available")

	print(f"Organization Name: {org_name}")
	print(f"Creation Date: {creation_date}")
	print(f"Email(s): {emails}")



#Host Discovery

try:
		
	ip = socket.gethostbyname(domain)
	print(f"The domain '{domain}' resolves to IP address: {ip}")
	print (f"This host is live")
except socket.gaierror:
	print(f"The domain " + domain + " does not resolve.")


#Port Scanning

	

print("Retrieving port data...")


print("Retrieving port services data...")
	

full_scan = scan_target(ip)
	

os_name = get_local_os_info()
print(os_name)


#Vulnerability Assessment

full_scan.append(os_name)
for service in full_scan:
	vulns = get_vulnerabilities(str(service))

	print(f"Vulnerabilities for get vulnerabilities {service}: {vulns}")


#Snort persistent scanning and alerting

SNORT_PATH = r"C:\Snort\bin\snort.exe"
CONFIG_PATH = r"C:\Snort\etc\snort.conf"
INTERFACE = "5"  
LOG_DIR = r"C:\Snort\log"
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

		
def watch_alerts():
    print("Viewing alert file...\n")
    seen = 0
    while True:
        if os.path.exists(ALERT_FILE):
            with open(ALERT_FILE, 'r') as f:
                lines = f.readlines()
                new_alerts = lines[seen:]
                if new_alerts:
                    for alert in new_alerts:
                        print(f"[ALERT] {alert.strip()}")
                    seen = len(lines)
        time.sleep(1)

snort_proc = start_snort()
print("Snort started. Monitoring traffic...")

try:
    alert_thread = Thread(target=watch_alerts, daemon=True)
    alert_thread.start()

    while True:
    	time.sleep(1)

except Exception as e:
    print(f"Error: {e}")

finally:
    print("\nStopping Snort...")
    snort_proc.terminate()
    snort_proc.wait()
    print("Snort stopped.")
	
#Wireshark periodic scans and text doc reports
		
#Reporting functionalities
		
	
			
	
	





	



			

	
