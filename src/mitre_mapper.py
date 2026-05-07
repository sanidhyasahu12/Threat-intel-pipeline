def map_to_mitre(enrichment_result):
    """
    Looks at the enriched IOC data and maps it to a MITRE ATT&CK technique.
    Think of this as a translation layer:
    'What the IOC IS' --> 'What attack technique it represents'
    """

    ttp = {
        "technique_id": "T1000",
        "technique_name": "Unknown Technique",
        "tactic": "Unknown Tactic",
        "description": "Could not map to a known MITRE ATT&CK technique."
    }

    # Pull out the Shodan data to read tags and ports
    shodan = enrichment_result.get("shodan", {})
    tags = shodan.get("tags", [])
    ports = shodan.get("open_ports", [])

    # Pull out VirusTotal verdict
    vt = enrichment_result.get("virustotal", {})
    verdict = vt.get("verdict", "CLEAN")

    # --- MAPPING LOGIC ---

    # Check for Tor exit nodes
    if "tor" in tags:
        ttp = {
            "technique_id": "T1090.003",
            "technique_name": "Multi-hop Proxy",
            "tactic": "Command and Control",
            "description": "Adversaries use Tor to anonymize C2 traffic and hide their origin."
        }

    # Check for VPN usage
    elif "vpn" in tags:
        ttp = {
            "technique_id": "T1090",
            "technique_name": "Proxy",
            "tactic": "Command and Control",
            "description": "Adversaries use VPNs to mask their true location and route traffic."
        }

    # Check for open port 22 — SSH brute force common attack vector
    elif 22 in ports and verdict in ["MALICIOUS", "SUSPICIOUS"]:
        ttp = {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "description": "Open SSH port on malicious IP suggests brute force or unauthorized access attempts."
        }

    # Check for open port 445 — SMB, used in ransomware/lateral movement
    elif 445 in ports:
        ttp = {
            "technique_id": "T1021.002",
            "technique_name": "SMB/Windows Admin Shares",
            "tactic": "Lateral Movement",
            "description": "Port 445 open on malicious IP suggests SMB exploitation or lateral movement."
        }

    # Check for open port 3389 — RDP, common for remote access attacks
    elif 3389 in ports:
        ttp = {
            "technique_id": "T1021.001",
            "technique_name": "Remote Desktop Protocol",
            "tactic": "Lateral Movement",
            "description": "Port 3389 open suggests RDP-based remote access or brute force."
        }

    # Generic malicious IP with no specific signature
    elif verdict == "MALICIOUS":
        ttp = {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "tactic": "Command and Control",
            "description": "Malicious IP with no specific port/tag signature. Likely C2 communication."
        }

    return ttp