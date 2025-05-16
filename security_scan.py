import os
import io
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
from models import save_scan_to_reports


def get_local_os_info():
    # OS of scanning machine
    os_name = platform.system()
    os_version = platform.version()
    os_release = platform.release()
    os = f"Local OS: {os_name}, Version: {os_version}, Release: {os_release}"
    return os

def scan_target(ip):
    nm = nmap.PortScanner()  # Create Nmap scanner object
    if isinstance(ip, list):
        raise TypeError("Expected a single IP address as a string, but got a list.")
    
    print(f"Scanning {ip}...\n")
    try:
        nm.scan(hosts=ip, arguments="-Pn -sS -sV --top-ports 100")  # Run service detection scan
    except Exception as e:
        print(f"Error during scan: {e}")
        return []

    # Check if the host exists in the scan results
    if ip not in nm.all_hosts():
        print(f"No results found for {ip}. The host may be unreachable or invalid.")
        return []

    cve_items = []

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

# Vulnerability Assessment
# NVD API for CVE data

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
                high += 1
            elif severity == "CRITICAL":
                critical += 1

    global total_high, total_critical
    total_high += high
    total_critical += critical
    print(f"High: {high}, Critical: {critical}")
    print(f"Total: {high + critical}")
    return "\n".join(formatted_cves) if formatted_cves else f"No HIGH or CRITICAL vulnerabilities found for {service_name}."

def getWhoIs(domain_list):
    w = ""
    for domain in domain_list:
        # Perform WHOIS domain lookup
        w += f"Results for domain: {domain}\n"
        result = whois.whois(domain)

        org_name = result.get("org", "Not available")
        creation_date = result.get("creation_date", "Not available")
        emails = result.get("emails", "Not available")

        w += f"Organization Name: {org_name}\n"
        w += f"Creation Date: {creation_date}\n"
        w += f"Email(s): {emails}\n"
        w += "\n"

        # Host Discovery
        try:
            ip = socket.gethostbyname(domain)
            w += (f"IP: IP address for {domain}: {ip}\n")
            w += (f"The domain '{domain}' resolves to IP address: {ip}")
            w += (f"This host is live")
            ip_list = ip 
        except socket.gaierror:
            w += f"IP: The domain {domain} does not resolve to an ip.\n"

    print(w)
    return w

# Save results 
'''def save_to_csv(scan_summary, filename="scan_results.csv"):
    
    # Dynamically determine the root folder of the script
    root_folder = os.path.dirname(os.path.abspath(__file__))  # Get the directory of the current script
    file_path = os.path.join(root_folder, filename)  # Construct the full path to save the file in the script's directory

    # Add "Feedback" to the fieldnames
    keys = ["domain", "ip", "high", "critical", "os", "whois", "Nmap_info", "No. of Vulnerabilities", "Vulnerabilities", "Feedback"]
    with open(file_path, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        for row in scan_summary:
            writer.writerow(row)
    print(f"\nScan results saved to {file_path}")

    # Push scan_summary to the reports table
    save_scan_to_reports(scan_summary)

    return scan_summary'''

def save_to_csv(scan_summary, filename="scan_results.csv"):
    root_folder = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(root_folder, filename)

    keys = ["domain", "ip", "high", "critical", "os", "whois", "Nmap_info", "No. of Vulnerabilities", "Vulnerabilities"]

    # Check if file already exists
    file_exists = os.path.isfile(file_path)

    with open(file_path, mode='a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=keys)

        # Write header only if the file does not already exist
        if not file_exists:
            writer.writeheader()

        for row in scan_summary:
            writer.writerow(row)

    print(f"\nScan results appended to {file_path}")
    return scan_summary

# Reporting functionalities

def generate_graph(scan_summary):
    # Create directory if it doesn't exist
    output_dir = os.path.join("security_scan", "graphs")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "vulnerability_graph.png")

    # Extract data
    ips = [entry["ip"] for entry in scan_summary]
    high_counts = [entry["high"] for entry in scan_summary]
    critical_counts = [entry["critical"] for entry in scan_summary]

    # Plot
    x = range(len(ips))
    bar_width = 0.4

    plt.figure(figsize=(10, 6))
    plt.bar(x, high_counts, width=bar_width, label='HIGH', color='orange')
    plt.bar([p + bar_width for p in x], critical_counts, width=bar_width, label='CRITICAL', color='red')

    plt.xlabel('IP Address')
    plt.ylabel('CVE Count')
    plt.title('High & Critical CVE Counts by IP Address')
    plt.xticks([p + bar_width / 2 for p in x], ips, rotation=45)
    plt.legend()
    plt.tight_layout()

    plt.savefig(output_path)
    plt.close()

    print(f"Vulnerability summary graph saved to: {output_path}")


def generate_feedback(total_high, total_critical):
    feedback = {
        "rating": "",
        "message": ""
    }

    total_vulnerabilities = total_high + total_critical

    # Determine rating based on the number of vulnerabilities
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

    # Adjust feedback if critical vulnerabilities exceed high vulnerabilities
    if total_critical > total_high:
        feedback["rating"] = "Very Poor"
        feedback["message"] += " Critical vulnerabilities outnumber high vulnerabilities, which is a serious concern."

    return feedback

def perform_reconnaissance(ip):
    scan_summary = []
    urls = input("Enter your domain or IP address to begin")
    domain_list = [value.strip() for value in urls.split(',')]
    ip_list = ""
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
    return f"Reconnaissance executed for IP: {ip}"

def launch_ids(ip):
    urls = input("Enter your domain or IP address to begin")

    domain_list = [value.strip() for value in urls.split(',')]
     # Get the IP address of the first domain
    scan_summary =[]
    print("Launching IDS...")
    # Perform IDS launch
    print("Performing IDS launch...")
    print("This feature is unavailable at this time. Please contact Support")
    save_to_csv(scan_summary)
    return f"IDS launched for IP: {ip}"


    

def perform_network_scan(ip):
    scan_summary = []
    urls = input("Enter your IP address(es) to begin (comma-separated): ")

    ip_list = [value.strip() for value in urls.split(',')]

    print("Performing network scan...")
    for ip in ip_list:
        full_scan = scan_target(ip)  # Pass each IP as a string
        scan_summary.append({
            "ip": ip,
            "Nmap_info": full_scan,
        })

    save_to_csv(scan_summary)
    return f"Network scan completed for IP: {ip}"

def comprehensive_scan(ip):
    scan_summary = []
    urls = input("Enter your domain or IP address(es) to begin (comma-separated): ")

    domain_list = [value.strip() for value in urls.split(',')]
    ip_list = [socket.gethostbyname(domain) for domain in domain_list if domain]  # Resolve domains to IPs

    print("Performing comprehensive scan...")
    whois_data = getWhoIs(domain_list)
    os_name = get_local_os_info()
    vulnerabilities = []

    full_scan = []
    for ip in ip_list:
        scan_results = scan_target(ip)  # Pass each IP as a string
        full_scan.extend(scan_results)  # Collect results

    feedback = generate_feedback(total_high, total_critical)

    for service in full_scan:
        vulns = get_vulnerabilities(str(service))
        vulnerabilities.append(vulns)

    scan_summary.append({
        "domain": domain_list,
        "ip": ip_list,
        "high": total_high,
        "critical": total_critical,
        "os": os_name,
        "whois": whois_data,
        "Nmap_info": full_scan,
        "No. of Vulnerabilities": total_high + total_critical,
        "Vulnerabilities": vulnerabilities,
        "Feedback": feedback,
    })

    save_to_csv(scan_summary)
    generate_graph(scan_summary)
    return f"Comprehensive scan completed for IP: {ip}"
    



    
    



# Perform Reconnaissance
#perform_reconnaissance()

# Perform Network Scan

#perform_network_scan()

# Perform Comprehensive Scan
#comprehensive_scan()
#launch_ids()

# Generate Feedback
#feedback = generate_feedback(total_high, total_critical)
#print(f"Rating: {feedback['rating']}")
#print(f"Message: {feedback['message']")




















