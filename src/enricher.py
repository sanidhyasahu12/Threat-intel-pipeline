import requests
import os
import re
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")


def detect_ioc_type(ioc):
    """
    Figures out whether the IOC is an IP, domain, or file hash.
    """
    # IP pattern: four numbers separated by dots e.g. 192.168.1.1
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    # Hash pattern: MD5 (32), SHA1 (40), or SHA256 (64) hex characters
    hash_pattern = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")

    if ip_pattern.match(ioc):
        return "ip"
    elif hash_pattern.match(ioc):
        return "hash"
    else:
        return "domain"


def check_virustotal(ioc, ioc_type):
    """
    Calls the correct VirusTotal endpoint based on IOC type.
    IP, domain, and hash each have different API URLs.
    """
    print(f"  [VT] Checking {ioc} ({ioc_type}) on VirusTotal...")

    # Pick the right endpoint based on type
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            return {
                "source": "VirusTotal",
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_engines": total,
                "verdict": "MALICIOUS" if malicious > 5 else "SUSPICIOUS" if malicious > 0 else "CLEAN"
            }
        else:
            return {"source": "VirusTotal", "error": f"Status code {response.status_code}"}

    except Exception as e:
        return {"source": "VirusTotal", "error": str(e)}


def check_shodan(ip):
    """
    Shodan only works for IPs — not domains or hashes.
    """
    print(f"  [SD] Checking {ip} on Shodan...")

    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"

    try:
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            return {
                "source": "Shodan",
                "country": data.get("country_name", "Unknown"),
                "org": data.get("org", "Unknown"),
                "open_ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "tags": data.get("tags", [])
            }
        else:
            return {"source": "Shodan", "error": f"Status code {response.status_code}"}

    except Exception as e:
        return {"source": "Shodan", "error": str(e)}


def enrich_ioc(ioc):
    """
    Master function — detects IOC type, runs the right checks,
    returns a complete enrichment report.
    """
    print(f"\n[*] Enriching IOC: {ioc}")
    print("-" * 40)

    ioc_type = detect_ioc_type(ioc)
    print(f"  [*] Detected type: {ioc_type.upper()}")

    results = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "virustotal": check_virustotal(ioc, ioc_type)
    }

    # Shodan only makes sense for IPs
    if ioc_type == "ip":
        results["shodan"] = check_shodan(ioc)
    else:
        results["shodan"] = {"source": "Shodan", "note": f"Shodan skipped — IOC is a {ioc_type}, not an IP"}

    return results