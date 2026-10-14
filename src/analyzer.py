import math
import re
import urllib.parse
import dns.resolver
import whois
from datetime import datetime

class PhishingAnalyzer:
    def __init__(self, raw_url: str):
        self.raw_url = raw_url.strip()
        self.parsed_url = urllib.parse.urlparse(
            self.raw_url if "://" in self.raw_url else f"http://{self.raw_url}"
        )
        self.domain = self.parsed_url.netloc.split(":")[0] or self.parsed_url.path.split("/")[0]
        self.risk_score = 0
        self.findings = []
        self.whois_data = {}

    def calculate_entropy(self, text: str) -> float:
        """Calculate Shannon Entropy to detect DGA or randomized strings."""
        if not text:
            return 0.0
        entropy = 0.0
        for x in set(text):
            p_x = float(text.count(x)) / len(text)
            entropy -= p_x * math.log2(p_x)
        return round(entropy, 2)

    def analyze_heuristics(self):
        """Analyze URL structure, length, patterns, and anomalies."""
        # 1. IP Address Host Check
        ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if re.match(ip_pattern, self.domain):
            self.risk_score += 35
            self.findings.append("URL uses an explicit IPv4 address instead of a domain name.")

        # 2. URL Length Check
        if len(self.raw_url) > 75:
            self.risk_score += 15
            self.findings.append(f"Excessive URL length ({len(self.raw_url)} characters).")

        # 3. Shannon Entropy Check
        domain_entropy = self.calculate_entropy(self.domain)
        if domain_entropy > 4.2:
            self.risk_score += 20
            self.findings.append(f"High domain entropy detected ({domain_entropy}) — potential DGA.")

        # 4. Subdomain Depth Check
        domain_parts = self.domain.split(".")
        if len(domain_parts) > 3:
            self.risk_score += 20
            self.findings.append(f"High subdomain depth detected ({len(domain_parts) - 2} subdomains).")

        # 5. Phishing Keywords Check
        phish_keywords = ["login", "verify", "account", "update", "secure", "banking", "signin", "paypal", "microsoft", "google", "wallet"]
        found_keywords = [kw for kw in phish_keywords if kw in self.raw_url.lower() and not self.domain.endswith(f"{kw}.com")]
        if found_keywords:
            self.risk_score += 15
            self.findings.append(f"Contains targeted phishing keyword(s): {', '.join(found_keywords)}")

        # 6. Embedded Symbols Check
        if "@" in self.raw_url:
            self.risk_score += 25
            self.findings.append("URL contains '@' symbol (potential credential masking/redirection).")

    def check_dns_records(self):
        """Query MX records to verify domain infrastructure."""
        try:
            dns.resolver.resolve(self.domain, "MX")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception):
            self.risk_score += 10
            self.findings.append("No valid Mail Exchange (MX) DNS records found for domain.")

    def check_whois_age(self):
        """Query WHOIS registration age to identify newly spun up domains."""
        try:
            w = whois.whois(self.domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age_days = (datetime.now() - creation_date).days
                self.whois_data = {
                    "registrar": str(w.registrar),
                    "creation_date": creation_date.strftime("%Y-%m-%d"),
                    "age_days": age_days
                }
                if age_days < 30:
                    self.risk_score += 30
                    self.findings.append(f"Newly registered domain detected (Age: {age_days} days). High phishing risk.")
                elif age_days < 90:
                    self.risk_score += 15
                    self.findings.append(f"Recently registered domain (Age: {age_days} days).")
            else:
                self.whois_data = {"status": "Creation date unavailable"}
        except Exception:
            self.whois_data = {"status": "WHOIS lookup failed or blocked"}

    def run_full_analysis(self) -> dict:
        self.analyze_heuristics()
        self.check_dns_records()
        self.check_whois_age()

        risk_level = "LOW"
        if self.risk_score >= 60:
            risk_level = "CRITICAL"
        elif self.risk_score >= 35:
            risk_level = "HIGH"
        elif self.risk_score >= 15:
            risk_level = "MEDIUM"

        return {
            "url": self.raw_url,
            "domain": self.domain,
            "risk_score": min(self.risk_score, 100),
            "risk_level": risk_level,
            "findings": self.findings,
            "whois": self.whois_data
        }