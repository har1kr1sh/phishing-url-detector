#!/usr/bin/env python3
"""
Phishing URL & Threat Intelligence Analyzer Engine
Author: Hari Krishnan (@har1kr1sh)
Role: SOC L2 / Detection Engineering Portfolio
"""

import argparse
import os
from colorama import Fore, Style
from src.analyzer import PhishingAnalyzer
from src.intel_enrichment import ThreatIntelEnricher
from src.utils import print_cli_report, export_json_report

def print_banner():
    """Load and print the ASCII banner from banner/banner.txt."""
    banner_path = os.path.join("banner", "banner.txt")
    if os.path.exists(banner_path):
        with open(banner_path, "r") as f:
            # Fixed Fore.CYN to Fore.CYAN here:
            print(Fore.CYAN + f.read() + Style.RESET_ALL)
    else:
        print(f"{Fore.CYAN}[ Phishing URL & Threat Intelligence Analyzer ] - @har1kr1sh{Style.RESET_ALL}")

def process_url(url: str, enricher: ThreatIntelEnricher) -> dict:
    analyzer = PhishingAnalyzer(url)
    res = analyzer.run_full_analysis()
    res["virustotal"] = enricher.query_virustotal(res["domain"])
    res["urlhaus"] = enricher.query_urlhaus(url)
    print_cli_report(res)
    return res

def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Automated Phishing URL and Threat Intel Analyzer for SOC Triage.")
    parser.add_argument("-u", "--url", help="Target URL or domain to analyze")
    parser.add_argument("-f", "--file", help="File containing a list of URLs to scan")
    parser.add_argument("-o", "--output", help="Path to export JSON output results")
    args = parser.parse_args()

    enricher = ThreatIntelEnricher(config_path="config/config.txt")

    if not args.url and not args.file:
        try:
            user_input = input(f"{Fore.YELLOW}[?] Enter Phishing URL or domain to analyze (or press Enter to exit): {Style.RESET_ALL}").strip()
            if not user_input:
                print("Exiting tool. Stay safe out there!")
                return
            process_url(user_input, enricher)
            return
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            return

    urls_to_scan = []
    if args.url:
        urls_to_scan.append(args.url)
    elif args.file:
        if os.path.exists(args.file):
            with open(args.file, "r") as f:
                urls_to_scan = [line.strip() for line in f if line.strip()]
        else:
            print(f"{Fore.RED}[!] Error: File '{args.file}' not found.{Style.RESET_ALL}")
            return

    all_results = []
    for url in urls_to_scan:
        res = process_url(url, enricher)
        all_results.append(res)

    if args.output:
        export_json_report(all_results if len(all_results) > 1 else all_results[0], args.output)

if __name__ == "__main__":
    main()
