import whois
import socket
import threading
import nmap
from ipwhois import IPWhois

urls = input("Enter domain(s) separated by commas without https or www ")

domain_list = [value.strip() for value in urls.split(',')]

def scan_port(ip, port):
	
	# Create a socket object
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	sock.settimeout(10)  # Set timeout for the connection
	result = sock.connect_ex((ip, int(port)))  # Try to connect to the port
	if result == 0:
			
		print(f"Port {port} is open")
	else:
		print(f"Port {port} seems closed or filtered")

	sock.close()  # Close the socket


def get_services(ip, port):
	nm = nmap.PortScanner()

	# Perform a scan on the target IP for the specified port
	nm.scan(ip, str(port), arguments='-sV')  # -sV enables service version detection
    
	desired_ports = [22, 80, 443]
	service_versions =[]
    
	# Check the protocols for the scanned host
	for proto in nm[ip].all_protocols():
		lport = nm[ip][proto].keys()
		for port in lport:
			if port in desired_ports:
				service = nm[ip][proto][port].get('name','Unknown')
				version = nm[ip][proto][port].get('version','Unknown')
				service_versions.append(f"Port {port}: {service} ({version})")
	return service_versions
				
	

	

def get_vulnerabilities(service_name):
	# Example API call to a vulnerability database
	url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=" + service_name + "&keywordExactMatch?"
	response = requests.get(url)
	if response.status_code == 200:
		return response.json()  # Return the list of vulnerabilities
	return []

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

	scan_port(ip,"22")
	scan_port(ip,"80")
	scan_port(ip,"443")

	print("Retrieving port services data...")
	#execution stalls here then times out even after 30secs

	service_name1 = get_services(ip,22)
	service_name2 = get_services(ip,80)
	service_name3 = get_services(ip,443)

	print(service_name1)
	print(service_name2)
	print(service_name3)


	#Vulnerability Assessment

	
	#vulnerabilities = get_vulnerabilities(service_name)
			#if vulnerabilities:
				#print(f"Vulnerabilities for {service_name}: {vulnerabilities}")
			#else:
				#print(f"No known vulnerabilities for {service_name}")
	





	



			

	
