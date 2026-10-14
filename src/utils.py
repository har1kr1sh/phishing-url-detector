import json
from colorama import Fore, Style, init

init(autoreset=True)

def print_cli_report(results: dict):
    """Render a color-coded CLI report for triage."""
    risk = results["risk_level"]
    color = Fore.GREEN
    if risk == "CRITICAL":
        color = Fore.RED + Style.BRIGHT
    elif risk == "HIGH":
        color = Fore.LIGHTRED_EX
    elif risk == "MEDIUM":
        color = Fore.YELLOW

    print("\n" + "=" * 65)
    print(f" {Fore.CYAN}PHISHING URL DETECTOR & INTEL REPORT{Style.RESET_ALL} ")
    print("=" * 65)
    print(f" Target URL  : {results['url']}")
    print(f" Domain      : {results['domain']}")
    print(f" Risk Level  : {color}{risk}{Style.RESET_ALL} (Score: {results['risk_score']}/100)")
    print("-" * 65)

    print(f"\n {Fore.LIGHTBLUE_EX}[+] Heuristic Findings:{Style.RESET_ALL}")
    if results["findings"]:
        for finding in results["findings"]:
            print(f"   {Fore.RED}![Style.RESET_ALL} {finding}")
    else:
        print(f"   {Fore.GREEN}✓{Style.RESET_ALL} No structural anomalies detected.")

    print(f"\n {Fore.LIGHTBLUE_EX}[+] WHOIS Intelligence:{Style.RESET_ALL}")
    for k, v in results.get("whois", {}).items():
        print(f"   • {k.capitalize()}: {v}")

    print(f"\n {Fore.LIGHTBLUE_EX}[+] Threat Intelligence Enrichment:{Style.RESET_ALL}")
    vt = results.get("virustotal", {})
    uh = results.get("urlhaus", {})
    print(f"   • VirusTotal : {vt.get('status', 'N/A')} (Malicious: {vt.get('malicious', 0)})")
    print(f"   • URLhaus    : {uh.get('status', 'N/A')}")
    print("=" * 65 + "\n")

def export_json_report(results, filename: str = "output_report.json"):
    """Export analysis results to a structured JSON file."""
    with open(filename, "w") as f:
        json.dump(results, f, indent=4)
    print(f"[+] Detailed JSON report exported to '{filename}'.")