# backend/nmapScanner.py

import subprocess
import xml.etree.ElementTree as ET

NMAP_EXECUTABLE_PATH = r"C:/Program Files (x86)/Nmap/nmap.exe"

def scan(domain):
    print(f"Starting Nmap FAST PORT scan for {domain}...")
    risky_ports = {
        21: "FTP (File Transfer Protocol)",
        22: "SSH (Secure Shell)",
        23: "Telnet (Unencrypted Remote Login)",
        25: "SMTP (Email Protocol)",
    }
    findings = []
    
    try:
        command = [
            NMAP_EXECUTABLE_PATH,
            "-F",      # Fast scan mode
            domain,
            "-oX", "-"  # Output in XML format
        ]
        
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=True)
        
        root = ET.fromstring(result.stdout)
        
        for port in root.findall('.//port'):
            portid = int(port.get('portid'))
            state = port.find('./state').get('state')
            
            if state == 'open' and portid in risky_ports:
                findings.append(f"Suspicious open port found: {portid} ({risky_ports[portid]}).")

    except Exception as e:
        error_msg = f"An unexpected error occurred during Nmap scan: {e}"
        print(error_msg)
        findings.append(error_msg)
        
    print("Nmap scan finished.")
    return findings