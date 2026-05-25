import requests
import pandas as pd
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def calculate_severity(indicator):
    indicator = indicator.lower()

    if indicator.startswith("https://"):
        return "High"

    elif indicator.startswith("http://"):
        return "Medium"

    elif ".exe" in indicator or ".sh" in indicator or ".zip" in indicator:
        return "Critical"

    else:
        return "Low"


def fetch_urlhaus():
    print(Fore.CYAN + "[+] Fetching URLhaus threat feed...")

    response = requests.get(URLHAUS_CSV, timeout=20)

    if response.status_code != 200:
        print(Fore.RED + "[-] Failed to fetch URLhaus data")
        return []

    lines = response.text.splitlines()
    clean_lines = [line for line in lines if not line.startswith("#")]

    indicators = []

    for line in clean_lines[:50]:
        parts = line.split(",")

        if len(parts) >= 3:
            indicator = parts[2].replace('"', '')
            severity = calculate_severity(indicator)

            indicators.append({
                "source": "URLhaus",
                "indicator_type": "malicious_url",
                "indicator": indicator,
                "date_added": parts[1].replace('"', ''),
                "threat": "malware_url",
                "confidence": "high",
                "severity": severity
            })

    return indicators


def print_summary(df):
    print("\n" + Fore.YELLOW + "========== Threat Intelligence Summary ==========")
    print(Fore.GREEN + f"Total Indicators Collected: {len(df)}")

    print("\nSeverity Count:")
    print(df["severity"].value_counts().to_string())

    print("\nTop 10 Indicators:")
    print(df[["indicator", "severity", "confidence"]].head(10).to_string(index=False))

    print(Fore.YELLOW + "================================================\n")


def save_report(indicators):
    df = pd.DataFrame(indicators)
    df.drop_duplicates(subset=["indicator"], inplace=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    csv_path = f"data/threat_indicators_{timestamp}.csv"
    report_path = f"reports/threat_report_{timestamp}.txt"

    df.to_csv(csv_path, index=False)

    with open(report_path, "w") as report:
        report.write("Threat Intelligence Aggregator Report\n")
        report.write("=" * 50 + "\n\n")
        report.write(f"Generated on: {datetime.now()}\n")
        report.write(f"Total indicators collected: {len(df)}\n\n")

        report.write("Severity Summary\n")
        report.write("-" * 20 + "\n")
        report.write(df["severity"].value_counts().to_string())
        report.write("\n\n")

        report.write("Detailed Indicators\n")
        report.write("-" * 20 + "\n")
        report.write(df.to_string(index=False))

    print_summary(df)

    print(Fore.GREEN + f"[+] CSV saved: {csv_path}")
    print(Fore.GREEN + f"[+] Report saved: {report_path}")


def main():
    indicators = fetch_urlhaus()

    if indicators:
        save_report(indicators)
        print(Fore.GREEN + "[+] Threat intelligence aggregation completed.")
    else:
        print(Fore.RED + "[-] No indicators collected.")


if __name__ == "__main__":
    main()