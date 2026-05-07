from colorama import Fore, Style, init

# Initialize colorama so colors work on Windows terminal
init(autoreset=True)

def print_alert(enrichment_result, mitre_result):
    """
    Takes the enriched IOC + MITRE mapping and prints a
    colour-coded alert to the terminal. Red = bad. Green = clean.
    """

    ioc = enrichment_result.get("ioc", "Unknown")
    vt = enrichment_result.get("virustotal", {})
    shodan = enrichment_result.get("shodan", {})
    verdict = vt.get("verdict", "CLEAN")

    print("\n" + "=" * 50)

    # Colour the header based on severity
    if verdict == "MALICIOUS":
        print(Fore.RED + f"  🚨 ALERT: MALICIOUS IOC DETECTED")
    elif verdict == "SUSPICIOUS":
        print(Fore.YELLOW + f"  ⚠️  WARNING: SUSPICIOUS IOC")
    else:
        print(Fore.GREEN + f"  ✅ CLEAN: No threats detected")

    print("=" * 50)

    # IOC details
    print(f"\n  IOC          : {ioc}")
    print(f"  VT Verdict   : {verdict}")
    print(f"  VT Engines   : {vt.get('malicious_count', 0)}/{vt.get('total_engines', 0)} flagged malicious")

    # Shodan details
    if "error" not in shodan:
        print(f"  Country      : {shodan.get('country', 'Unknown')}")
        print(f"  Organization : {shodan.get('org', 'Unknown')}")
        print(f"  Open Ports   : {shodan.get('open_ports', [])}")
        print(f"  Tags         : {shodan.get('tags', [])}")

    # MITRE mapping
    print(f"\n  MITRE ATT&CK :")
    print(f"  Technique ID : {mitre_result.get('technique_id')}")
    print(f"  Technique    : {mitre_result.get('technique_name')}")
    print(f"  Tactic       : {mitre_result.get('tactic')}")
    print(f"  Description  : {mitre_result.get('description')}")

    print("\n" + "=" * 50 + "\n")