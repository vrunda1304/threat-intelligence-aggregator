# Threat Intelligence Aggregator

## Overview
This project collects and analyzes malicious indicators from live threat intelligence feeds using Python and Kali Linux.

## Features
- URLhaus threat feed integration
- IOC extraction and parsing
- Severity scoring
- CSV report generation
- Threat summary dashboard
- Kali Linux IOC verification
- WHOIS / DIG / NSLOOKUP / CURL analysis

## Tools Used
- Python
- Pandas
- Requests
- Colorama
- Kali Linux

## Project Workflow
Threat Feed → IOC Collection → Severity Classification → Report Generation → IOC Verification

## How to Run

```bash
pip install -r requirements.txt
python3 main.py
```

## Verification Commands (Kali Linux)

```bash
whois domain.com
nslookup domain.com
dig domain.com
curl -I http://domain.com
```