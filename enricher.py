import requests
import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")


def check_virustotal(ioc):
    print(f"  [VT] Checking {ioc} on VirusTotal...")
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
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
    print(f"\n[*] Enriching IOC: {ioc}")
    print("-" * 40)
    results = {
        "ioc": ioc,
        "virustotal": check_virustotal(ioc),
        "shodan": check_shodan(ioc)
    }
    return results