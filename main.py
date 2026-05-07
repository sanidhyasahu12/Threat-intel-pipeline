import json
import os
from src.enricher import enrich_ioc
from src.mitre_mapper import map_to_mitre
from src.alerter import print_alert

def load_iocs(filepath):
    """
    Reads IOCs from data/iocs.txt — one per line.
    Skips blank lines and comment lines starting with #
    """
    iocs = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                iocs.append(line)
    return iocs

def save_report(result, mitre, output_dir="output"):
    """
    Saves the full enrichment report as a JSON file in the output folder.
    """
    filename = f"{output_dir}/{result['ioc'].replace('.', '_')}.json"
    report = {
        "ioc": result["ioc"],
        "enrichment": result,
        "mitre": mitre
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=4)
    print(f"  [+] Report saved to {filename}")

def main():
    print("\n" + "="*50)
    print("   THREAT INTEL PIPELINE — STARTING")
    print("="*50)

    # Load IOCs from file
    iocs = load_iocs("data/iocs.txt")

    if not iocs:
        print("\n[!] No IOCs found in data/iocs.txt — add some IPs and try again.")
        return

    print(f"\n[*] Loaded {len(iocs)} IOC(s) to process\n")

    # Process each IOC
    for ioc in iocs:
        # Step 1: Enrich
        enrichment = enrich_ioc(ioc)

        # Step 2: Map to MITRE ATT&CK
        mitre = map_to_mitre(enrichment)

        # Step 3: Print alert
        print_alert(enrichment, mitre)

        # Step 4: Save report
        save_report(enrichment, mitre)

    print("\n[✓] Pipeline complete. Check the output/ folder for reports.\n")

if __name__ == "__main__":
    main()