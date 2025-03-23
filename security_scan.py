import whois
import platform
import pandas as pd
import requests
import socket
import threading
import nmap
from ipwhois import IPWhois

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
			item = product + " " + version  # Ensure proper spacing
			cve_items.append(item)  # Append to the list
		

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
	for entry in cve_list:
		cve = entry.get("cve", {})
		cve_id = cve.get("id", "N/A")
		description = next((desc["value"] for desc in cve.get("descriptions", []) if desc["lang"] == "en"), "No description available")
		severity = "N/A"
		if "metrics" in cve:
			cvss_v3 = cve["metrics"].get("cvssMetricV30", [])
			if cvss_v3:
				severity = cvss_v3[0]["cvssData"]["baseSeverity"]

		formatted_cves.append(f"**{cve_id}**\nSeverity: {severity}\nDescription: {description}\n")

	return "\n".join(formatted_cves)



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
	

	os = get_local_os_info()
	print(os)


	#Vulnerability Assessment

	full_scan.append(os)
	for service in full_scan:
		vulns = get_vulnerabilities(str(service))

		print(f"Vulnerabilities for get vulnerabilities {service}: {vulns}")
			
	
	





	



			

	
