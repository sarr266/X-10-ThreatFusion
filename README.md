# X-10 ThreatFusion

**Intelligence Command Platform | 10 Sources. Total Control.**

![giphy](https://github.com/user-attachments/assets/d5270fb7-6a73-4343-b508-4e5064308c52)

## Overview

X-10 ThreatFusion is a unified threat intelligence platform that correlates indicators across 10 premier security data sources, providing comprehensive threat analysis from a single command center.

## Key Features

- **Multi-Source Intelligence**: Integrates VirusTotal, Shodan, AlienVault OTX, IPInfo, AbuseIPDB, URLhaus, URLscan, IP Detective, GetIPIntel, and Ransomware.live
- **Dual Analysis Modes**: Single indicator analysis or batch processing
- **Advanced Ransomware Tracking**: Two-phase analysis - group intelligence → victim domain correlation
- **Real-Time Correlation**: Parallel API queries with automated threat scoring
- **Flexible Export**: JSON and TXT format support

## Use Cases

- Incident response & threat hunting
- IOC validation & OSINT investigations
- APT & ransomware group tracking
- Bulk indicator enrichment

## Tech Stack

- **Frontend**: Streamlit (Python)
- **Backend**: Python with modular API clients
- **Data Processing**: JSON-based aggregation & correlation
- **Architecture**: Session-based state management with parallel query execution

## How It Works

1. **Input** - Enter IP, domain, hash, or ransomware group
2. **Query** - Select and query 1-10 intelligence sources simultaneously
3. **Correlate** - Automated threat scoring and cross-source analysis
4. **Analyze** - For ransomware groups: extract victims → query victim domains across all sources
5. **Export** - Download results in JSON or TXT format

## Project Structure
```
x10-threatfusion/
├── apis/           # Modular API client classes
├── utils/          # Data processing helpers
├── app.py          # Main Streamlit application
```


Contributions welcome! Please open an issue or submit a pull request.

---

**X-10 ThreatFusion** - Command your intelligence, dominate the threat landscape.




