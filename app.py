"""
Intelligence Aggregator - Main Streamlit Application
Integrates multiple threat intelligence sources into one place
"""

import streamlit as st
import pandas as pd
from typing import Dict, Any
import logging
from datetime import datetime
import time

# Import our modules
from apis import (
    VirusTotalAPI,
    ShodanAPI,
    OTXAlienVaultAPI,
    IPInfoAPI,
    AbuseIPDBAPI,
    URLHausAPI,
    URLscanAPI,
)
from utils import (
    Config,
    classify_observable,
    get_threat_level,
    extract_key_findings,
    create_summary_report,
    get_analytics_data,
    format_results_for_export,
    parse_indicators_from_file,
    validate_batch_indicators,
    export_batch_results_json,
    export_batch_results_txt,
    create_individual_batch_reports,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Streamlit page config
st.set_page_config(
    page_title=Config.PAGE_TITLE,
    page_icon=Config.PAGE_ICON,
    layout=Config.LAYOUT,
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown("""
<style>
    .threat-critical { color: #FF0000; font-weight: bold; }
    .threat-high { color: #FF6600; font-weight: bold; }
    .threat-medium { color: #FFCC00; font-weight: bold; }
    .threat-low { color: #0099FF; font-weight: bold; }
    .threat-clean { color: #00CC00; font-weight: bold; }
    
    .metric-box {
        background-color: #f0f2f6;
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)


def initialize_session_state():
    """Initialize session state variables"""
    if "results" not in st.session_state:
        st.session_state.results = {}
    if "observable" not in st.session_state:
        st.session_state.observable = ""
    if "last_query" not in st.session_state:
        st.session_state.last_query = None
    if "batch_results" not in st.session_state:
        st.session_state.batch_results = {}
    if "batch_mode" not in st.session_state:
        st.session_state.batch_mode = False


def get_api_clients() -> Dict[str, Any]:
    """Initialize API clients based on configuration"""
    clients = {}
    
    if Config.VIRUSTOTAL_API_KEY:
        try:
            clients["VirusTotal"] = VirusTotalAPI(Config.VIRUSTOTAL_API_KEY)
        except Exception as e:
            logger.error(f"Failed to initialize VirusTotal: {e}")
    
    if Config.SHODAN_API_KEY:
        try:
            clients["Shodan"] = ShodanAPI(Config.SHODAN_API_KEY)
        except Exception as e:
            logger.error(f"Failed to initialize Shodan: {e}")
    
    if Config.OTX_API_KEY:
        try:
            clients["AlienVault OTX"] = OTXAlienVaultAPI(Config.OTX_API_KEY)
        except Exception as e:
            logger.error(f"Failed to initialize OTX: {e}")
    
    if Config.IPINFO_API_KEY:
        try:
            clients["IPInfo"] = IPInfoAPI(Config.IPINFO_API_KEY)
        except Exception as e:
            logger.error(f"Failed to initialize IPInfo: {e}")
    
    if Config.ABUSEIPDB_API_KEY:
        try:
            clients["AbuseIPDB"] = AbuseIPDBAPI(Config.ABUSEIPDB_API_KEY)
        except Exception as e:
            logger.error(f"Failed to initialize AbuseIPDB: {e}")
    
    if Config.URLSCAN_API_KEY:
        try:
            clients["URLscan"] = URLscanAPI(Config.URLSCAN_API_KEY)
        except Exception as e:
            logger.error(f"Failed to initialize URLscan: {e}")
    
    # URLhaus doesn't require API key
    try:
        clients["URLhaus"] = URLHausAPI()
    except Exception as e:
        logger.error(f"Failed to initialize URLhaus: {e}")
    
    return clients


def run_analysis(observable: str, selected_sources: list) -> Dict[str, Any]:
    """
    Run analysis across selected sources
    """
    results = {}
    clients = get_api_clients()
    
    for source_name, client in clients.items():
        if source_name not in selected_sources:
            continue
        
        try:
            result = client.analyze(observable)
            results[source_name] = result
        except Exception as e:
            logger.error(f"Error querying {source_name}: {e}")
            results[source_name] = {"error": str(e)}
    
    return results


def run_batch_analysis(indicators: list, selected_sources: list) -> Dict[str, Dict[str, Any]]:
    """
    Run analysis for multiple indicators
    Returns dict with indicator as key and results as value
    """
    batch_results = {}
    clients = get_api_clients()
    
    total_indicators = len(indicators)
    total_sources = len(selected_sources)
    total_operations = total_indicators * total_sources
    
    progress_bar = st.progress(0)
    status_text = st.empty()
    current_operation = 0
    
    for idx, indicator_data in enumerate(indicators, 1):
        indicator = indicator_data["indicator"]
        status_text.text(f"Processing {idx}/{total_indicators}: {indicator}")
        
        indicator_results = {}
        
        for source_name, client in clients.items():
            if source_name not in selected_sources:
                continue
            
            try:
                result = client.analyze(indicator)
                indicator_results[source_name] = result
                time.sleep(0.1)  # Small delay to avoid rate limiting
            except Exception as e:
                logger.error(f"Error querying {source_name} for {indicator}: {e}")
                indicator_results[source_name] = {"error": str(e)}
            
            current_operation += 1
            progress = int((current_operation / total_operations) * 100)
            progress_bar.progress(progress)
        
        batch_results[indicator] = indicator_results
    
    progress_bar.empty()
    status_text.empty()
    
    return batch_results


def display_header():
    """Display application header"""
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.title("🔍 Intelligence Aggregator")
        st.markdown("""
        Unified threat intelligence platform that aggregates data from multiple sources
        including VirusTotal, Shodan, AlienVault OTX, and more.
        """)
    
    with col2:
        is_valid, message = Config.validate_config()
        if is_valid:
            st.success(message)
        else:
            st.error(message)


def display_single_input():
    """Display single indicator input"""
    col1, col2 = st.columns([3, 1])
    
    with col1:
        observable = st.text_input(
            "Enter observable (IP, Domain, URL, or Hash):",
            placeholder="e.g., 8.8.8.8 or example.com",
            help="Can be an IP address, domain name, URL, or file hash (MD5, SHA1, SHA256)",
        )
    
    with col2:
        st.markdown("")  # Spacing
        st.markdown("")
        analyze_button = st.button("🚀 Analyze", use_container_width=True)
    
    # Source selection
    selected_sources = display_source_selection()
    
    return observable, analyze_button, selected_sources, "single", None


def display_batch_input():
    """Display batch input"""
    st.markdown("**Upload Indicator File:**")
    
    uploaded_file = st.file_uploader(
        "Choose a file (TXT or CSV)",
        type=["txt", "csv"],
        help="Upload a file containing indicators (one per line or CSV format)"
    )
    
    analyze_button = st.button("🚀 Analyze Batch", use_container_width=True)
    
    # Source selection
    selected_sources = display_source_selection()
    
    return None, analyze_button, selected_sources, "batch", uploaded_file


def display_input_section():
    """Display input and configuration section"""
    st.subheader("📋 Query Configuration")
    
    # Mode selection
    mode = st.radio(
        "Select Analysis Mode:",
        ["Single Indicator", "Batch Analysis"],
        horizontal=True
    )
    
    st.markdown("---")
    
    if mode == "Single Indicator":
        return display_single_input()
    else:
        return display_batch_input()


def display_source_selection():
    """Display source selection checkboxes"""
    st.markdown("**Select Intelligence Sources:**")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        vt = st.checkbox("VirusTotal", value=bool(Config.VIRUSTOTAL_API_KEY), disabled=not Config.VIRUSTOTAL_API_KEY)
        shodan = st.checkbox("Shodan", value=bool(Config.SHODAN_API_KEY), disabled=not Config.SHODAN_API_KEY)
        otx = st.checkbox("AlienVault OTX", value=bool(Config.OTX_API_KEY), disabled=not Config.OTX_API_KEY)
    
    with col2:
        ipinfo = st.checkbox("IPInfo", value=bool(Config.IPINFO_API_KEY), disabled=not Config.IPINFO_API_KEY)
        abuseipdb = st.checkbox("AbuseIPDB", value=bool(Config.ABUSEIPDB_API_KEY), disabled=not Config.ABUSEIPDB_API_KEY)
        urlscan = st.checkbox("URLscan", value=bool(Config.URLSCAN_API_KEY), disabled=not Config.URLSCAN_API_KEY)
    
    with col3:
        urlhaus = st.checkbox("URLhaus", value=True)
    
    selected_sources = []
    if vt:
        selected_sources.append("VirusTotal")
    if shodan:
        selected_sources.append("Shodan")
    if otx:
        selected_sources.append("AlienVault OTX")
    if ipinfo:
        selected_sources.append("IPInfo")
    if abuseipdb:
        selected_sources.append("AbuseIPDB")
    if urlscan:
        selected_sources.append("URLscan")
    if urlhaus:
        selected_sources.append("URLhaus")
    
    return selected_sources


def display_results_overview(results: Dict[str, Any], observable: str):
    """Display results overview section"""
    st.subheader("📊 Analysis Overview")
    
    analytics = get_analytics_data(results)
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "Threat Level",
            analytics["threat_level"],
            delta=None,
        )
    
    with col2:
        st.metric(
            "Malicious Detections",
            analytics["malicious_detections"],
            delta=None,
        )
    
    with col3:
        st.metric(
            "Suspicious Detections",
            analytics["suspicious_detections"],
            delta=None,
        )
    
    with col4:
        st.metric(
            "Sources Queried",
            analytics["sources_queried"],
            f"{analytics['sources_failed']} failed",
        )
    
    # Key findings
    st.markdown("**Key Findings:**")
    findings = extract_key_findings(results)
    for finding in findings:
        st.write(f"• {finding}")


def display_virustotal_results(data: Dict[str, Any]):
    """Display VirusTotal results"""
    st.subheader("🦠 VirusTotal Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    # Threat statistics
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Malicious", data.get("malicious", 0))
    with col2:
        st.metric("Suspicious", data.get("suspicious", 0))
    with col3:
        st.metric("Undetected", data.get("undetected", 0))
    
    # Additional details
    if data.get("type") == "ip":
        st.write(f"**Country:** {data.get('country')}")
        st.write(f"**ASN:** {data.get('asn')}")
        st.write(f"**AS Owner:** {data.get('as_owner')}")
    
    elif data.get("type") == "domain":
        if data.get("categories"):
            st.write(f"**Categories:** {', '.join(data.get('categories', {}).values())}")
    
    elif data.get("type") == "file":
        st.write(f"**File Size:** {data.get('file_size')} bytes")
        st.write(f"**File Type:** {data.get('file_type')}")
        if data.get("tags"):
            st.write(f"**Tags:** {', '.join(data.get('tags', []))}")


def display_shodan_results(data: Dict[str, Any]):
    """Display Shodan results"""
    st.subheader("🔌 Shodan Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write(f"**Country:** {data.get('country_name')}")
        st.write(f"**City:** {data.get('city')}")
        st.write(f"**ISP:** {data.get('isp')}")
        st.write(f"**Organization:** {data.get('organization')}")
    
    with col2:
        st.write(f"**Latitude:** {data.get('latitude')}")
        st.write(f"**Longitude:** {data.get('longitude')}")
        st.write(f"**OS:** {data.get('os')}")
    
    # Open ports
    if data.get("ports"):
        st.write(f"**Open Ports:** {', '.join(map(str, data.get('ports', [])))}")
    
    # Hostnames
    if data.get("hostnames"):
        st.write(f"**Hostnames:** {', '.join(data.get('hostnames', []))}")


# def display_otx_results(data: Dict[str, Any]):
#     """Display AlienVault OTX results"""
#     st.subheader("🚨 AlienVault OTX Results")
    
#     if "error" in data:
#         st.error(f"Error: {data['error']}")
#         return
    
#     # Basic info
#     col1, col2 = st.columns(2)
    
#     with col1:
#         st.write(f"**Reputation:** {data.get('reputation')}")
#         st.write(f"**Type:** {data.get('type_title')}")
    
#     with col2:
#         st.write(f"**Validity:** {data.get('validity')}")
    
#     # Pulses
#     pulses = data.get("pulses", [])
#     if pulses:
#         st.write(f"**Found in {len(pulses)} Threat Pulses:**")
        
#         for pulse in pulses[:5]:  # Show top 5
#             with st.expander(f"🔴 {pulse.get('name')}"):
#                 st.write(f"**Author:** {pulse.get('author')}")
#                 st.write(f"**Created:** {pulse.get('created')}")
#                 st.write(f"**Description:** {pulse.get('description')}")
                
#                 # Handle None values and convert dicts/objects to strings
#                 malware_families = pulse.get("malware_families") or []
#                 if malware_families and isinstance(malware_families, list):
#                     family_names = [str(item) if not isinstance(item, dict) else item.get('name', str(item)) for item in malware_families]
#                     st.write(f"**Malware Families:** {', '.join(family_names)}")
                
#                 attack_ids = pulse.get("attack_ids") or []
#                 if attack_ids and isinstance(attack_ids, list):
#                     attack_id_strs = [str(item) if not isinstance(item, dict) else item.get('id', str(item)) for item in attack_ids]
#                     st.write(f"**Attack IDs:** {', '.join(attack_id_strs)}")
                
#                 industries = pulse.get("industries") or []
#                 if industries and isinstance(industries, list):
#                     industry_names = [str(item) if not isinstance(item, dict) else item.get('name', str(item)) for item in industries]
#                     st.write(f"**Industries:** {', '.join(industry_names)}")
                
#                 if pulse.get("adversary"):
#                     st.write(f"**Adversary:** {pulse.get('adversary')}")
                
#                 st.markdown(f"[View on OTX]({pulse.get('url')})")
#     else:
#         st.info("No threat pulses found for this observable")


def display_otx_results(data: Dict[str, Any]):
    """Display AlienVault OTX results - COMPREHENSIVE VERSION with error handling"""
    st.subheader("🚨 AlienVault OTX Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    # Basic info
    col1, col2, col3 = st.columns(3)
    
    with col1:
        reputation = data.get('reputation', 0)
        st.write(f"**Reputation:** {reputation}")
        st.write(f"**Type:** {data.get('type_title', 'N/A')}")
    
    with col2:
        st.write(f"**Validity:** {data.get('validity', 'N/A')}")
        pulse_count = data.get('pulse_count', 0)
        st.write(f"**Threat Pulses:** {pulse_count}")
    
    with col3:
        # Use country_name only to avoid duplication
        country = data.get("country_name")
        if country:
            st.write(f"**Country:** {country}")
        asn = data.get("asn")
        if asn:
            st.write(f"**ASN:** {asn}")
    
    # WHOIS Information (for domains)
    whois_data = data.get("whois")
    if whois_data and isinstance(whois_data, str) and len(whois_data) > 10:
        with st.expander("📋 WHOIS Information", expanded=True):
            # Display in a scrollable text area with better formatting
            st.text_area("WHOIS Data", whois_data, height=300, label_visibility="collapsed")
    
    # Related Domains - Removed as endpoint returns 404
    
    # Passive DNS Records
    passive_dns = data.get("passive_dns_records", [])
    if passive_dns and len(passive_dns) > 0:
        with st.expander(f"🌐 Passive DNS Records ({len(passive_dns)} found)"):
            for idx, record in enumerate(passive_dns, 1):
                hostname = record.get('hostname', 'N/A')
                address = record.get('address', 'N/A')
                record_type = record.get('record_type', 'N/A')
                first_seen = record.get('first', 'N/A')
                last_seen = record.get('last', 'N/A')
                
                st.write(f"**{idx}. {hostname}** → {address} ({record_type})")
                st.caption(f"First seen: {first_seen} | Last seen: {last_seen}")
                
                if idx < len(passive_dns):
                    st.markdown("---")
    
    # Associated URLs
    associated_urls = data.get("associated_urls", [])
    if associated_urls and len(associated_urls) > 0:
        with st.expander(f"🔗 Associated URLs ({len(associated_urls)} found)"):
            for idx, url_entry in enumerate(associated_urls, 1):
                url = url_entry.get('url', 'N/A')
                domain = url_entry.get('domain', 'N/A')
                hostname = url_entry.get('hostname', 'N/A')
                date = url_entry.get('date', 'N/A')
                
                st.write(f"**{idx}. {url}**")
                st.caption(f"Domain: {domain} | Hostname: {hostname} | Date: {date}")
                
                if idx < len(associated_urls):
                    st.markdown("---")
    
    # HTTP Scans
    http_scans = data.get("http_scans", [])
    if http_scans and len(http_scans) > 0:
        with st.expander(f"🔍 HTTP Scans ({len(http_scans)} fields found)", expanded=True):
            st.markdown("**Port 443 (HTTPS) Scan Results:**")
            for idx, scan in enumerate(http_scans, 1):
                field = scan.get('field', 'N/A')
                value = scan.get('value', 'N/A')
                st.write(f"**{field}:** {value}")
            st.info("These are the HTTP/HTTPS scan results showing domains, titles, and other web server information.")
    
    # Malware Samples
    malware_samples = data.get("malware_samples", [])
    if malware_samples and len(malware_samples) > 0:
        with st.expander(f"🦠 Malware Samples ({len(malware_samples)} found)", expanded=True):
            st.warning("⚠️ This indicator is associated with known malware!")
            for idx, sample in enumerate(malware_samples[:10], 1):
                col1, col2 = st.columns([3, 1])
                with col1:
                    st.code(sample.get('hash', 'N/A'))
                with col2:
                    st.metric("Detections", sample.get('detections', 0))
                st.caption(f"Date: {sample.get('date', 'N/A')}")
                if idx < len(malware_samples[:10]):
                    st.markdown("---")
    
    # Pulses (Threat Intelligence)
    pulses = data.get("pulses", [])
    if pulses and len(pulses) > 0:
        st.write(f"**Found in {len(pulses)} Threat Pulses:**")
        
        for pulse in pulses[:5]:
            with st.expander(f"🔴 {pulse.get('name', 'Unknown')}"):
                st.write(f"**Author:** {pulse.get('author', 'N/A')}")
                st.write(f"**Created:** {pulse.get('created', 'N/A')}")
                
                description = pulse.get('description', '')
                if description:
                    st.write(f"**Description:** {description}")
                
                malware_families = pulse.get("malware_families") or []
                if malware_families and isinstance(malware_families, list) and len(malware_families) > 0:
                    family_names = [str(item) if not isinstance(item, dict) else item.get('name', str(item)) for item in malware_families]
                    if family_names:
                        st.write(f"**Malware Families:** {', '.join(family_names)}")
                
                attack_ids = pulse.get("attack_ids") or []
                if attack_ids and isinstance(attack_ids, list) and len(attack_ids) > 0:
                    attack_id_strs = [str(item) if not isinstance(item, dict) else item.get('id', str(item)) for item in attack_ids]
                    if attack_id_strs:
                        st.write(f"**Attack IDs:** {', '.join(attack_id_strs)}")
                
                industries = pulse.get("industries") or []
                if industries and isinstance(industries, list) and len(industries) > 0:
                    industry_names = [str(item) if not isinstance(item, dict) else item.get('name', str(item)) for item in industries]
                    if industry_names:
                        st.write(f"**Industries:** {', '.join(industry_names)}")
                
                adversary = pulse.get("adversary")
                if adversary:
                    st.write(f"**Adversary:** {adversary}")
                
                pulse_url = pulse.get('url')
                if pulse_url:
                    st.markdown(f"[View on OTX]({pulse_url})")
    else:
        # Check if we have ANY other data
        has_other_data = any([
            passive_dns,
            associated_urls,
            http_scans,
            malware_samples,
            whois_data and isinstance(whois_data, str) and len(whois_data) > 10
        ])
        
        if has_other_data:
            st.info("ℹ️ No threat pulses found, but other intelligence data is available above")
        else:
            st.info("✅ No threat intelligence found for this observable in OTX database")


def display_abuseipdb_results(data: Dict[str, Any]):
    """Display AbuseIPDB results"""
    st.subheader("🚫 AbuseIPDB Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    # Abuse score
    score = data.get("abuse_confidence_score", 0)
    
    # Color code based on score
    if score > 75:
        score_color = "🔴"
    elif score > 25:
        score_color = "🟠"
    else:
        score_color = "🟢"
    
    st.metric("Abuse Confidence Score", f"{score_color} {score}%")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write(f"**Country:** {data.get('country_name')}")
        st.write(f"**ISP:** {data.get('isp')}")
        st.write(f"**Usage Type:** {data.get('usage_type')}")
    
    with col2:
        st.write(f"**Whitelisted:** {data.get('is_whitelisted')}")
        st.write(f"**Total Reports:** {data.get('total_reports')}")
        st.write(f"**Last Reported:** {data.get('last_reported_at')}")


def display_ipinfo_results(data: Dict[str, Any]):
    """Display IPInfo results"""
    st.subheader("ℹ️ IPInfo Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write(f"**Hostname:** {data.get('hostname')}")
        st.write(f"**Organization:** {data.get('org')}")
        st.write(f"**City:** {data.get('city')}")
        st.write(f"**Region:** {data.get('region')}")
    
    with col2:
        st.write(f"**Country:** {data.get('country')}")
        st.write(f"**Timezone:** {data.get('timezone')}")
        st.write(f"**Location:** {data.get('loc')}")
    
    # Privacy info
    if data.get("privacy"):
        privacy = data.get("privacy", {})
        if privacy.get("vpn") or privacy.get("proxy") or privacy.get("tor"):
            st.warning("⚠️ Privacy/Proxy Usage Detected")
            st.write(f"- VPN: {privacy.get('vpn')}")
            st.write(f"- Proxy: {privacy.get('proxy')}")
            st.write(f"- Tor: {privacy.get('tor')}")


def display_urlhaus_results(data: Dict[str, Any]):
    """Display URLhaus results"""
    st.subheader("🌐 URLhaus Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    if data.get("status") == "not_found":
        st.info("No malicious URLs found in URLhaus")
        return
    
    if data.get("type") == "url":
        st.write(f"**Status:** {data.get('status')}")
        st.write(f"**Threat:** {data.get('threat')}")
        
        if data.get("tags"):
            st.write(f"**Tags:** {', '.join(data.get('tags', []))}")
    
    elif data.get("type") == "domain":
        st.write(f"**URLs Found:** {data.get('url_count')}")
        
        if data.get("urls"):
            st.write("**Recent URLs:**")
            for url in data.get("urls", []):
                col1, col2 = st.columns([4, 1])
                with col1:
                    st.write(url.get("url"))
                with col2:
                    st.caption(url.get("threat", ""))


def display_urlscan_results(data: Dict[str, Any]):
    """Display URLscan results"""
    st.subheader("🔍 URLscan Results")
    
    if "error" in data:
        st.error(f"Error: {data['error']}")
        return
    
    if data.get("status") == "not_found":
        st.info("No scan results found for this observable")
        return
    
    if data.get("status") == "submitted":
        st.info(f"✅ URL submitted for scanning!")
        st.write(f"**Scan ID:** {data.get('scan_id')}")
        st.markdown(f"[View Full Scan]({data.get('scan_url')})")
        return
    
    # Display scan results
    scan_count = data.get("scan_count", 0)
    st.write(f"**Total Scans:** {scan_count}")
    
    scans = data.get("scans", [])
    if scans:
        st.write("**Recent Scans:**")
        
        for idx, scan in enumerate(scans[:5], 1):
            with st.expander(f"🔗 Scan {idx} - {scan.get('url', scan.get('domain', 'N/A'))}"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write(f"**URL:** {scan.get('url')}")
                    st.write(f"**Domain:** {scan.get('domain')}")
                    st.write(f"**IP:** {scan.get('ip')}")
                    st.write(f"**Country:** {scan.get('country')}")
                
                with col2:
                    st.write(f"**ASN:** {scan.get('asn')}")
                    st.write(f"**ASN Name:** {scan.get('asnname')}")
                    st.write(f"**Timestamp:** {scan.get('timestamp')}")
                
                # Threat statistics
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Malicious", scan.get("malicious", 0))
                with col2:
                    st.metric("Suspicious", scan.get("suspicious", 0))
                with col3:
                    st.metric("Unspecified", scan.get("unspecified", 0))
                
                # Screenshot and scan link
                if scan.get("screenshot"):
                    st.image(scan.get("screenshot"), caption="Screenshot")
                
                st.markdown(f"[Full Scan Report]({scan.get('scan_url')})")


def display_results(results: Dict[str, Any], observable: str):
    """Display all results for single indicator"""
    st.markdown("---")
    
    # Overview section
    display_results_overview(results, observable)
    
    st.markdown("---")
    st.subheader("🔬 Detailed Results")
    
    # Display results by source
    if results.get("VirusTotal") and "error" not in results.get("VirusTotal", {}):
        display_virustotal_results(results["VirusTotal"])
        st.markdown("---")
    
    if results.get("Shodan") and "error" not in results.get("Shodan", {}):
        display_shodan_results(results["Shodan"])
        st.markdown("---")
    
    if results.get("AlienVault OTX") and "error" not in results.get("AlienVault OTX", {}):
        display_otx_results(results["AlienVault OTX"])
        st.markdown("---")
    
    if results.get("AbuseIPDB") and "error" not in results.get("AbuseIPDB", {}):
        display_abuseipdb_results(results["AbuseIPDB"])
        st.markdown("---")
    
    if results.get("IPInfo") and "error" not in results.get("IPInfo", {}):
        display_ipinfo_results(results["IPInfo"])
        st.markdown("---")
    
    if results.get("URLhaus") and "error" not in results.get("URLhaus", {}):
        display_urlhaus_results(results["URLhaus"])
        st.markdown("---")
    
    if results.get("URLscan") and "error" not in results.get("URLscan", {}):
        display_urlscan_results(results["URLscan"])


def display_batch_results(batch_results: Dict[str, Dict[str, Any]], indicators_metadata: list):
    """Display batch analysis results - individual report for each indicator"""
    st.markdown("---")
    st.subheader("📊 Batch Analysis Results")
    
    st.info(f"Total Indicators Analyzed: {len(batch_results)}")
    
    # Display each indicator's results
    for idx, (indicator, results) in enumerate(batch_results.items(), 1):
        metadata = next((m for m in indicators_metadata if m["indicator"] == indicator), {})
        
        st.markdown("---")
        st.markdown(f"## Indicator {idx}/{len(batch_results)}: `{indicator}`")
        st.caption(f"Type: {metadata.get('type', 'Unknown')}")
        
        # Display full results for this indicator
        display_results(results, indicator)
        
        # Export options for individual indicator
        with st.expander(f"📥 Export Report for {indicator}"):
            col1, col2 = st.columns(2)
            
            with col1:
                json_data = format_results_for_export(results, indicator)
                st.download_button(
                    label="📄 Download as JSON",
                    data=json_data,
                    file_name=f"report_{indicator.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    key=f"json_{idx}"
                )
            
            with col2:
                text_report = create_summary_report(results, indicator)
                st.download_button(
                    label="📝 Download as Text",
                    data=text_report,
                    file_name=f"report_{indicator.replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                    key=f"txt_{idx}"
                )


def display_export_section(results: Dict[str, Any], observable: str):
    """Display export options for single indicator"""
    st.markdown("---")
    st.subheader("📥 Export Results")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        # Export as JSON
        json_data = format_results_for_export(results, observable)
        st.download_button(
            label="📄 Download as JSON",
            data=json_data,
            file_name=f"report_{observable}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
        )
    
    with col2:
        # Export as Text Report
        text_report = create_summary_report(results, observable)
        st.download_button(
            label="📝 Download as Text Report",
            data=text_report,
            file_name=f"report_{observable}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
        )
    
    with col3:
        st.info("💡 Use 'Copy to clipboard' button above to share results")


def display_batch_export_section(batch_results: Dict[str, Dict[str, Any]], indicators_metadata: list):
    """Display export options for batch results"""
    st.markdown("---")
    st.subheader("📥 Export All Batch Results")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Export complete batch as JSON
        json_data = export_batch_results_json(batch_results, indicators_metadata)
        st.download_button(
            label="📄 Download All as JSON",
            data=json_data,
            file_name=f"batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
        )
    
    with col2:
        # Export complete batch as text
        text_report = export_batch_results_txt(batch_results, indicators_metadata)
        st.download_button(
            label="📝 Download All as Text",
            data=text_report,
            file_name=f"batch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
        )
    
    # Individual reports ZIP
    st.markdown("---")
    st.info("💡 Individual reports for each indicator can be downloaded from their respective sections above")


def main():
    """Main application"""
    initialize_session_state()
    
    # Header
    display_header()
    
    st.markdown("---")
    
    # Input section
    observable, analyze_button, selected_sources, mode, uploaded_file = display_input_section()
    
    # Handle Single Indicator Analysis
    if mode == "single" and analyze_button and observable and selected_sources:
        # Validate observable
        obs_type = classify_observable(observable)
        if obs_type == "Unknown":
            st.error("❌ Invalid observable format. Please enter a valid IP, domain, URL, or hash.")
        else:
            st.info(f"🔎 Observable type detected: **{obs_type}**")
            
            # Run analysis
            with st.spinner("Analyzing..."):
                results = run_analysis(observable, selected_sources)
            
            # Store in session
            st.session_state.results = results
            st.session_state.observable = observable
            st.session_state.last_query = datetime.now()
            st.session_state.batch_mode = False
            
            # Display results
            display_results(results, observable)
            
            # Export section
            display_export_section(results, observable)
    
    # Handle Batch Analysis
    elif mode == "batch" and analyze_button and uploaded_file and selected_sources:
        # Read and parse file
        try:
            file_content = uploaded_file.read().decode("utf-8")
            indicators = parse_indicators_from_file(file_content)
            
            if not indicators:
                st.error("❌ No valid indicators found in the uploaded file.")
            else:
                # Validate indicators
                valid_indicators, invalid_indicators, summary = validate_batch_indicators(indicators)
                
                st.info(f"📋 File processed: {summary['total']} total, {summary['valid']} valid, {summary['invalid']} invalid")
                
                if invalid_indicators:
                    with st.expander(f"⚠️ {len(invalid_indicators)} Invalid Indicators"):
                        for invalid in invalid_indicators:
                            st.write(f"- {invalid['indicator']}: {invalid['reason']}")
                
                if valid_indicators:
                    # Store validated indicators in session state
                    st.session_state.valid_indicators = valid_indicators
                    st.session_state.batch_selected_sources = selected_sources
                    st.success(f"✅ Ready to analyze {len(valid_indicators)} indicators")
                
        except Exception as e:
            st.error(f"❌ Error processing file: {str(e)}")
    
    # Batch analysis execution (outside the file upload condition)
    if mode == "batch" and "valid_indicators" in st.session_state and st.session_state.valid_indicators:
        valid_indicators = st.session_state.valid_indicators
        
        if st.button("⚡ Start Batch Analysis", type="primary", use_container_width=True):
            selected_sources = st.session_state.get("batch_selected_sources", [])
            
            with st.spinner(f"Analyzing {len(valid_indicators)} indicators..."):
                batch_results = run_batch_analysis(valid_indicators, selected_sources)
            
            # Store in session
            st.session_state.batch_results = batch_results
            st.session_state.batch_mode = True
            st.session_state.last_query = datetime.now()
            
            st.success("✅ Batch analysis complete!")
            st.rerun()
    
    # Display batch results if they exist
    if mode == "batch" and st.session_state.batch_mode and st.session_state.batch_results:
        batch_results = st.session_state.batch_results
        valid_indicators = st.session_state.valid_indicators
        
        # Display batch results
        display_batch_results(batch_results, valid_indicators)
        
        # Batch export section
        display_batch_export_section(batch_results, valid_indicators)
    
    elif analyze_button and not observable and mode == "single":
        st.warning("⚠️ Please enter an observable to analyze")
    
    elif analyze_button and not uploaded_file and mode == "batch":
        st.warning("⚠️ Please upload a file containing indicators")
    
    elif analyze_button and not selected_sources:
        st.warning("⚠️ Please select at least one intelligence source")
    
    # Sidebar
    with st.sidebar:
        st.header("ℹ️ About")
        st.markdown("""
        **Intelligence Aggregator** is a unified threat intelligence platform
        that combines data from multiple sources including:
        
        - 🦠 VirusTotal
        - 🔌 Shodan
        - 🚨 AlienVault OTX
        - ⚠️ AbuseIPDB
        - ℹ️ IPInfo
        - 🌐 URLhaus
        - 🔍 URLscan
        
        **Supported Observable Types:**
        - IP addresses (IPv4)
        - Domains
        - URLs
        - File hashes (MD5, SHA1, SHA256)
        
        **Analysis Modes:**
        - Single Indicator: Analyze one observable
        - Batch Analysis: Upload file with multiple indicators
        
        **Features:**
        - Real-time threat intelligence
        - Multi-source correlation
        - Detailed threat analysis
        - Individual reports for each indicator
        - Export results as JSON or text
        """)
        
        st.markdown("---")
        
        st.header("⚙️ Configuration")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("🔄 Refresh API Status"):
                st.rerun()
        
        with col2:
            if st.button("🔐 Clear Session"):
                st.session_state.clear()
                st.success("Session cleared!")
        
        active_apis = Config.get_active_apis()
        st.write(f"**Active APIs: {len(active_apis)}**")
        
        for api_name in sorted(active_apis.keys()):
            st.write(f"✅ {api_name}")
        
        # Debug section
        with st.expander("🔧 Debug Info"):
            debug_info = Config.debug_config()
            for key, status in debug_info.items():
                st.write(f"{key}: {status}")


if __name__ == "__main__":
    main()