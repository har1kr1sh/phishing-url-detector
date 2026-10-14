import os
import requests

class ThreatIntelEnricher:
    def __init__(self, config_path: str = "config/config.txt"):
        self.api_keys = self._load_config(config_path)
        self.vt_api_key = self.api_keys.get("VIRUSTOTAL_API_KEY")

    def _load_config(self, path: str) -> dict:
        keys = {}
        if os.path.exists(path):
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        keys[k.strip()] = v.strip()
        return keys

    def query_urlhaus(self, url: str) -> dict:
        try:
            response = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    return {
                        "status": "MALICIOUS",
                        "threat": data.get("threat"),
                        "tags": data.get("tags", []),
                        "urlhaus_reference": data.get("urlhaus_reference")
                    }
            return {"status": "CLEAN_OR_UNKNOWN"}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}

    def query_virustotal(self, domain: str) -> dict:
        if not self.vt_api_key or self.vt_api_key == "your_virustotal_api_key_here" or self.vt_api_key == "your_actual_virustotal_api_key_here":
            return {"status": "SKIPPED", "reason": "No valid API key found in config/config.txt"}

        headers = {"x-apikey": self.vt_api_key}
        try:
            response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=5)
            if response.status_code == 200:
                stats = response.json()["data"]["attributes"]["last_analysis_stats"]
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "status": "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN"
                }
            return {"status": "NOT_FOUND"}
        except Exception as e:
            return {"status": "ERROR", "message": str(e)}