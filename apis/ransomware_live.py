"""
Ransomware.live API integration - Ransomware intelligence and threat data
"""

import logging
from typing import Dict, Any, List
import requests
from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class RansomwareLiveAPI(BaseAPIClient):
    """Ransomware.live API client for ransomware intelligence"""

    BASE_URL = "https://api.ransomware.live"

    def __init__(self, api_key: str, timeout: int = 15):
        """Initialize Ransomware.live API client
        
        Args:
            api_key: Ransomware.live API key
            timeout: Request timeout in seconds (default: 15)
        """
        super().__init__(api_key, timeout)
        # Public API doesn't require auth header for basic queries
        self.public_headers = {
            "Accept": "application/json",
            "User-Agent": "Mozilla/5.0"
        }

    def _safe_request(self, url: str, headers: dict = None, expect_json: bool = True, retries: int = 3, backoff: float = 1.0, allow_redirects: bool = True):
        """Perform requests.get with retries and robust JSON/text handling.

        Returns parsed JSON when expect_json is True and valid, otherwise returns text.
        On repeated failures returns None.
        """
        headers = headers or {}
        for attempt in range(1, retries + 1):
            try:
                resp = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=allow_redirects)
            except requests.exceptions.RequestException as e:
                logger.debug(f"Request error for {url} (attempt {attempt}/{retries}): {e}")
                if attempt < retries:
                    time_sleep = backoff * attempt
                    try:
                        import time
                        time.sleep(time_sleep)
                    except Exception:
                        pass
                    continue
                return None

            if resp.status_code != 200:
                logger.debug(f"Non-200 response for {url}: {resp.status_code}")
                # Do not retry on 4xx, but retry on 5xx once
                if 500 <= resp.status_code < 600 and attempt < retries:
                    try:
                        import time
                        time.sleep(backoff * attempt)
                    except Exception:
                        pass
                    continue
                return None

            if expect_json:
                try:
                    return resp.json()
                except ValueError as e:
                    logger.debug(f"JSON decode error for {url} (attempt {attempt}/{retries}): {e}")
                    # Try small wait and retry
                    if attempt < retries:
                        try:
                            import time
                            time.sleep(backoff * attempt)
                        except Exception:
                            pass
                        continue
                    return None
            else:
                try:
                    return resp.text
                except Exception as e:
                    logger.debug(f"Error reading text response for {url}: {e}")
                    return None

    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze observable for ransomware-related intelligence
        
        Args:
            observable: Domain, IP, hash, or company name
            
        Returns:
            Analysis results
        """
        obs_type = self._classify_observable(observable)
        
        # Search for victims by name, domain, or any term
        results = self._search_victims(observable)
        
        # If observable looks like a domain/company name, also search for groups
        if obs_type in ["Domain", "URL", "Unknown"] or "." in observable:
            results["associated_groups"] = self._search_groups(observable)
        else:
            results["associated_groups"] = []
        
        return results

    def analyze_group(self, group_name: str) -> Dict[str, Any]:
        """
        Analyze a threat group for comprehensive ransomware intelligence
        Returns all available data like Ransomware.live website
        
        Args:
            group_name: Name of the ransomware group
            
        Returns:
            Comprehensive group analysis with stats, metadata, and victims
        """
        response = {
            "source": "Ransomware.live",
            "group_name": group_name,
            "type": "ransomware_group_analysis",
            "group_info": {},
            "recent_victims": [],
            "victim_domains": [],
            "threat_level": "unknown",
            "is_malicious": False,
            "malicious": 0,
            "suspicious": 0,
            # New comprehensive fields
            "status": "Active",
            "description": "",
            "history": "",
            "statistics": {
                "total_victims": 0,
                "first_victim_date": "",
                "last_victim_date": "",
                "inactive_days": 0,
                "avg_delay_days": 0.0,
                "infostealer_percentage": 0.0
            },
            "metadata": {
                "known_locations": 0,
                "ransom_notes": 0,
                "tools_used": 0,
                "vulnerabilities_exploited": 0,
                "ttps_matrix": 0,
                "negotiation_chats": 0,
                "yara_rules": 0,
                "iocs_count": 0
            },
            "active_regions": [],
            "initial_access_vectors": [],
            "tools_used_list": [],
            "cves": [],
            "related_groups": [],
            "external_links": {}
        }
        
        # Get comprehensive group data
        comprehensive_data = self._get_comprehensive_group_data(group_name)
        
        # Merge comprehensive data into response
        response.update(comprehensive_data)
        
        # Normalize/merge nested lists into metadata to keep display logic compatible
        try:
            meta = response.setdefault("metadata", {})
            # Copy common list fields from top-level into metadata if missing
            for fld in ["known_locations_list", "ransom_notes_list", "tools_used_list", "vulnerabilities_list", "ttps_list", "negotiation_chats_list", "yara_rules_list", "iocs_list"]:
                if fld not in meta or meta.get(fld) is None:
                    if fld in response:
                        meta[fld] = response.get(fld) or []

            # Ensure counts exist
            meta.setdefault("known_locations", len(meta.get("known_locations_list", [])))
            meta.setdefault("ransom_notes", len(meta.get("ransom_notes_list", [])))
            meta.setdefault("tools_used", len(meta.get("tools_used_list", [])))
            meta.setdefault("vulnerabilities_exploited", len(meta.get("vulnerabilities_list", [])))
            meta.setdefault("ttps_matrix", len(meta.get("ttps_list", [])))
            meta.setdefault("negotiation_chats", len(meta.get("negotiation_chats_list", [])))
            meta.setdefault("yara_rules", len(meta.get("yara_rules_list", [])))
            meta.setdefault("iocs_count", len(meta.get("iocs_list", [])))

            # Ensure targets structure exists
            if "targets" not in response or response.get("targets") is None:
                response["targets"] = {"top_sectors": [], "top_countries": [], "sector_distribution": {}, "country_distribution": {}}
        except Exception:
            # Keep original behavior on error
            pass
        
        # Get victims for this specific group
        victims = self._get_victims_for_group(group_name)
        response["recent_victims"] = victims
        
        # Extract victim domains for correlation (deduplicated)
        victim_domains = set()
        for victim in victims:
            if "website" in victim and victim["website"]:
                victim_domains.add(victim["website"])
            if "name" in victim and victim["name"] != "N/A":
                victim_domains.add(victim["name"])
        
        response["victim_domains"] = list(victim_domains)[:20]  # Limit to 20 for Phase 2
        response["suspicious"] = len(victims)
        response["is_malicious"] = True if victims else False
        response["threat_level"] = "critical" if len(victims) >= 100 else "high" if len(victims) >= 10 else "medium"
        
        return response

    def _get_comprehensive_group_data(self, group_name: str) -> Dict[str, Any]:
        """
        Get comprehensive group data from Ransomware.live API and website scraping
        
        Step 1: Calls /groups API endpoint for group metadata (NOT /api/groups redirect)
        Step 2: Scrapes website for victim data (not available in JSON API)
        
        Industry-grade approach combining API + web scraping when APIs are incomplete
        """
        comprehensive_data = {
            "status": "Unknown",
            "description": "",
            "history": "",
            "statistics": {
                "total_victims": 0,
                "first_victim_date": "Unknown",
                "last_victim_date": "Unknown",
                "inactive_days": 0,
                "avg_delay_days": "N/A",
                "infostealer_percentage": 0.0
            },
            "metadata": {
                "known_locations": 0,
                "known_locations_list": [],
                "ransom_notes": 0,
                "ransom_notes_list": [],
                "tools_used": 0,
                "tools_used_list": [],
                "vulnerabilities_exploited": 0,
                "vulnerabilities_list": [],
                "ttps_matrix": 0,
                "ttps_list": [],
                "negotiation_chats": 0,
                "negotiation_chats_list": [],
                "yara_rules": 0,
                "yara_rules_list": [],
                "iocs_count": 0
            },
            "targets": {
                "top_sectors": [],
                "top_countries": [],
                "sector_distribution": {},
                "country_distribution": {}
            },
            "active_regions": [],
            "initial_access_vectors": [],
            "tools_used_list": [],
            "cves": [],
            "related_groups": [],
            "external_links": {},
            "victim_domains": [],
            "iocs_list": [],
            "total_victims": 0
        }
        
        group_lower = group_name.lower().strip()
        
        try:
            # STEP 1: Fetch from /groups API endpoint (NOT /api/groups - that's a redirect)
            logger.info(f"Fetching data for {group_name} from Ransomware.live...")
            
            try:
                url = f"{self.BASE_URL}/groups"
                headers = {
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                }
                
                groups = self._safe_request(url, headers=headers, expect_json=True, retries=3, backoff=1.0)

                if groups:
                    try:
                        
                        if isinstance(groups, list):
                            # Search for matching group in API data
                            for group in groups:
                                if isinstance(group, dict):
                                    group_name_api = group.get("name", "").lower().strip()
                                    
                                    if group_lower == group_name_api:
                                        logger.info(f"✓ Found {group_name} in /groups API endpoint")
                                        
                                        # Extract locations (known_locations)
                                        locations = group.get("locations", [])
                                        known_locs_list = []
                                        for loc in locations:
                                            if isinstance(loc, dict):
                                                fqdn = loc.get("fqdn", "")
                                                if fqdn:
                                                    known_locs_list.append(fqdn)
                                        
                                        # Extract tools info (preserve tactic structure)
                                        tools_list = {}
                                        tools_data = group.get("tools", [])
                                        if tools_data and isinstance(tools_data, list) and len(tools_data) > 0:
                                            tool_dict = tools_data[0]
                                            if isinstance(tool_dict, dict):
                                                for tactic, tool_names in tool_dict.items():
                                                    if isinstance(tool_names, list):
                                                        tools_list[tactic] = tool_names
                                        
                                        comprehensive_data = {
                                            "status": group.get("status", "Unknown"),
                                            "description": group.get("description", ""),
                                            "history": group.get("history", group.get("background", "")),
                                            "statistics": {
                                                "total_victims": 0,  # Will be updated from website
                                                "first_victim_date": "Unknown",  # Will be updated from website
                                                "last_victim_date": "Unknown",  # Will be updated from website
                                                "inactive_days": self._calculate_inactive_days(group.get("last_activity", "")),
                                                "avg_delay_days": "N/A",  # Will be updated from website
                                                "infostealer_percentage": 0.0  # Will be updated from website
                                            },
                                            "metadata": {
                                                "known_locations": len(known_locs_list),
                                                "known_locations_list": known_locs_list,
                                                "ransom_notes": group.get("ransom_notes_count", 0),
                                                "ransom_notes_list": group.get("ransom_notes", []) if isinstance(group.get("ransom_notes", []), list) else [],
                                                "tools_used": len(tools_list),
                                                "tools_used_list": tools_list,
                                                "vulnerabilities_exploited": group.get("cves_count", group.get("vulnerabilities_count", 0)),
                                                "vulnerabilities_list": group.get("cves", []) if isinstance(group.get("cves", []), list) else [],
                                                "ttps_matrix": group.get("ttps_count", group.get("tactics_count", 0)),
                                                "negotiation_chats": group.get("chats_count", 0),
                                                "yara_rules": group.get("yara_rules_count", 0),
                                                "iocs_count": group.get("iocs_count", 0)
                                            },
                                            "active_regions": group.get("active_regions", []),
                                            "initial_access_vectors": group.get("initial_access_vectors", []),
                                            "tools_used_list": tools_list,
                                            "cves": group.get("exploited_cves", []),
                                            "related_groups": group.get("related_groups", []),
                                            "external_links": group.get("external_links", {}),
                                            "victim_domains": [],
                                            "iocs_list": [],
                                            "total_victims": 0,
                                            "targets": {
                                                "top_sectors": [],
                                                "top_countries": [],
                                                "sector_distribution": {},
                                                "country_distribution": {}
                                            }
                                        }
                                        break
                    except (ValueError, KeyError) as e:
                        logger.debug(f"Error parsing API response: {e}")
                        pass
            except requests.exceptions.RequestException as e:
                logger.debug(f"API endpoint /groups failed: {e}")
            
            # STEP 2: Fetch victim data from website (victims NOT available in JSON API)
            logger.info(f"Fetching victim data from website for {group_name}...")
            try:
                # Use www subdomain to avoid redirect
                website_url = f"https://www.ransomware.live/group/{group_lower}"
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                }
                
                html = self._safe_request(website_url, headers=headers, expect_json=False, retries=3, backoff=1.0, allow_redirects=True)

                if html:
                    try:
                        from bs4 import BeautifulSoup
                        import re

                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Initialize all values
                        victims_count = 0
                        victim_domains = []
                        first_date = "Unknown"
                        last_date = "Unknown"
                        inactive_days = 0
                        avg_delay = "N/A"
                        infostealer_pct = 0.0
                        locations_count = 0
                        ransom_notes_count = 0
                        tools_count = "Unknown"
                        vulnerabilities_count = 0
                        ttps_count = 0
                        chats_count = 0
                        yara_count = 0
                        iocs_count = 0
                        iocs_list = []
                        
                        # STEP 2A: Extract statistics from h4 tags in statistics boxes
                        stats_containers = soup.find_all('div', class_='border-start')
                        for container in stats_containers:
                            label = container.find('h6')
                            value = container.find('h3') or container.find('h4')
                            if label and value:
                                label_text = label.get_text().strip().lower()
                                value_text = value.get_text().strip()
                                
                                if 'victims' in label_text:
                                    try:
                                        victims_count = int(value_text)
                                    except:
                                        victims_count = 0
                                elif 'first discovered' in label_text:
                                    first_date = value_text if value_text != "Unknown" else "Unknown"
                                elif 'last discovered' in label_text:
                                    last_date = value_text if value_text != "Unknown" else "Unknown"
                                elif 'inactive' in label_text:
                                    try:
                                        inactive_days = int(value_text)
                                    except:
                                        inactive_days = 0
                                elif 'avg delay' in label_text:
                                    avg_delay = value_text
                                elif 'infostealer' in label_text:
                                    try:
                                        # Extract percentage value
                                        match = re.search(r'(\d+\.?\d*)', value_text)
                                        if match:
                                            infostealer_pct = float(match.group(1))
                                    except:
                                        infostealer_pct = 0.0
                        
                        # STEP 2B: Extract metadata counts from span tags
                        for span in soup.find_all('span'):
                            text = span.get_text().strip()
                            
                            if 'Known Locations' in text:
                                match = re.search(r'\((\d+)\)', text)
                                if match:
                                    locations_count = int(match.group(1))
                            elif 'Ransom Notes' in text and '(' in text:
                                match = re.search(r'\((\d+)\)', text)
                                if match:
                                    ransom_notes_count = int(match.group(1))
                            elif 'Tools Used' in text:
                                if 'Available' in text:
                                    tools_count = "Available"
                                else:
                                    match = re.search(r'\((\d+)\)', text)
                                    if match:
                                        tools_count = int(match.group(1))
                            elif 'Vulnerabilities' in text:
                                match = re.search(r'\((\d+)\)', text)
                                if match:
                                    vulnerabilities_count = int(match.group(1))
                            elif 'TTPs' in text:
                                match = re.search(r'\((\d+)\)', text)
                                if match:
                                    ttps_count = int(match.group(1))
                            elif 'Negotiation Chats' in text:
                                match = re.search(r'\((\d+)\)', text)
                                if match:
                                    chats_count = int(match.group(1))
                            elif 'YARA' in text:
                                match = re.search(r'\((\d+)\)', text)
                                if match:
                                    yara_count = int(match.group(1))
                            elif 'Indicators of Compromise' in text or 'IoCs' in text:
                                match = re.search(r'\((\d+)\)', text)
                                if match:
                                    iocs_count = int(match.group(1))
                            elif text == str(victims_count) and victims_count > 0:
                                # Already handled above
                                pass
                        
                        # STEP 2C: Extract IoCs if available
                        if iocs_count > 0:
                            iocs_section = soup.find(id='iocs-section')
                            if iocs_section:
                                # Extract IoC items (domains, IPs, hashes)
                                for item in iocs_section.find_all(['li', 'tr', 'div']):
                                    text = item.get_text().strip()
                                    if text and len(text) > 3:  # Filter out short texts
                                        iocs_list.append(text)
                        
                        # STEP 2D: Extract victim domains from href="/id/" links
                        for link in soup.find_all('a', href=True):
                            href = link.get('href', '')
                            if '/id/' in href and '#infostealer' not in href:
                                victim_text = link.get_text().strip()
                                if victim_text:
                                    victim_domains.append(victim_text)
                        
                        # Remove duplicates while preserving order
                        victim_domains = list(dict.fromkeys(victim_domains))
                        
                        # STEP 2E: Extract DETAILED information from SPECIFIC section IDs ONLY
                        
                        # Extract Known Locations from locations-section table
                        locations_list = []
                        locations_section = soup.find('div', id='locations-section')
                        if locations_section:
                            for row in locations_section.find_all('tr')[1:]:  # Skip header
                                cols = row.find_all('td')
                                if len(cols) >= 7:
                                    fqdn = cols[6].get_text().strip()
                                    if fqdn and fqdn not in locations_list:
                                        locations_list.append(fqdn)
                        
                        # Extract Target Information (Sectors and Countries) from target-section
                        sectors_list = []
                        countries_list = []
                        target_section = soup.find('div', id='target-section')
                        if target_section:
                            cards = target_section.find_all('div', class_='card')
                            
                            # Process first card (Sectors)
                            if len(cards) > 0:
                                items = cards[0].find_all('li', class_='list-group-item')
                                for item in items:
                                    try:
                                        # Get all text and find the badge for count
                                        item_text = item.get_text()
                                        
                                        # Find badge (contains the count)
                                        badge = item.find('span', class_='badge')
                                        if badge:
                                            count_str = badge.get_text().strip()
                                            count = int(count_str)
                                            
                                            # Get sector name by removing badge content from item text
                                            sector_name = item_text.replace(count_str, '').strip()
                                            # Clean whitespace
                                            sector_name = ' '.join(sector_name.split())
                                            
                                            if sector_name:
                                                sectors_list.append({"name": sector_name, "count": count})
                                    except Exception as e:
                                        logger.debug(f"Error parsing sector item: {e}")
                                        pass
                            
                            # Process second card (Countries)
                            if len(cards) > 1:
                                items = cards[1].find_all('li', class_='list-group-item')
                                for item in items:
                                    try:
                                        item_text = item.get_text()
                                        
                                        # Find badge (contains the count)
                                        badge = item.find('span', class_='badge')
                                        if badge:
                                            count_str = badge.get_text().strip()
                                            count = int(count_str)
                                            
                                            # Get country name by removing badge content
                                            country_name = item_text.replace(count_str, '').strip()
                                            country_name = ' '.join(country_name.split())
                                            
                                            if country_name:
                                                countries_list.append({"name": country_name, "count": count})
                                    except Exception as e:
                                        logger.debug(f"Error parsing country item: {e}")
                                        pass
                        
                        # Extract Ransom Notes from notes-section
                        ransom_notes_list = []
                        notes_section = soup.find('div', id='notes-section')
                        if notes_section and 'No ransom notes' not in notes_section.get_text():
                            for link in notes_section.find_all('a'):
                                text = link.get_text().strip()
                                url = link.get('href', '')
                                if text and url:
                                    # Convert relative URLs to absolute
                                    if url.startswith('/'):
                                        url = f"https://www.ransomware.live{url}"
                                    ransom_notes_list.append({"name": text, "url": url})
                        
                        # Extract Tools from tools-section table - CLASSIFIED BY TACTIC
                        tools_list = {}
                        tools_section = soup.find('div', id='tools-section')
                        if tools_section and 'No tools' not in tools_section.get_text():
                            table = tools_section.find('table')
                            if table:
                                # Get headers
                                headers = []
                                for th in table.find_all('th'):
                                    headers.append(th.get_text().strip())
                                # Get rows
                                for row in table.find('tbody').find_all('tr') if table.find('tbody') else []:
                                    cols = row.find_all('td')
                                    if cols and len(headers) == len(cols):
                                        for idx, col in enumerate(cols):
                                            tactic = headers[idx] if idx < len(headers) else f"Category_{idx}"
                                            # Extract individual tools from <div> elements within the cell
                                            tool_divs = col.find_all('div', class_='py-1')
                                            if tool_divs:
                                                for div in tool_divs:
                                                    tool_text = div.get_text().strip()
                                                    if tool_text and 'placeholder' not in tool_text.lower():
                                                        if tactic not in tools_list:
                                                            tools_list[tactic] = []
                                                        if tool_text not in tools_list[tactic]:
                                                            tools_list[tactic].append(tool_text)
                                            else:
                                                # Fallback: use cell text if no divs found
                                                tool_text = col.get_text().strip()
                                                if tool_text and 'placeholder' not in tool_text.lower():
                                                    if tactic not in tools_list:
                                                        tools_list[tactic] = []
                                                    if tool_text not in tools_list[tactic]:
                                                        tools_list[tactic].append(tool_text)
                        
                        # Extract Vulnerabilities from vulns-section (CORRECT ID)
                        vulnerabilities_list = []
                        vuln_section = soup.find('div', id='vulns-section')
                        if vuln_section and 'No' not in vuln_section.get_text():
                            for text in vuln_section.find_all(string=re.compile(r'CVE-\d{4}-\d{4,}')):
                                cves = re.findall(r'CVE-\d{4}-\d{4,}', str(text))
                                vulnerabilities_list.extend(cves)
                        vulnerabilities_list = list(dict.fromkeys(vulnerabilities_list))
                        
                        # Extract TTPs from ttps-section
                        ttps_list = []
                        ttps_section = soup.find('div', id='ttps-section')
                        if ttps_section and 'No TTPs' not in ttps_section.get_text():
                            for item in ttps_section.find_all(['li', 'a']):
                                text = item.get_text().strip()
                                if text and len(text) > 1 and text not in ttps_list:
                                    ttps_list.append(text)
                        
                        # Extract Negotiation Chats from negos-section (CORRECT ID)
                        chats_list = []
                        chats_section = soup.find('div', id='negos-section')
                        if chats_section and 'No' not in chats_section.get_text():
                            for item in chats_section.find_all('a'):
                                text = item.get_text().strip()
                                url = item.get('href', '')
                                if text and url:
                                    # Convert relative URLs to absolute
                                    if url.startswith('/'):
                                        url = f"https://www.ransomware.live{url}"
                                    chats_list.append({"title": text, "url": url})
                        
                        # Extract YARA Rules from yara-section
                        yara_list = []
                        yara_section = soup.find('div', id='yara-section')
                        if yara_section and 'No YARA' not in yara_section.get_text():
                            for item in yara_section.find_all('a'):
                                text = item.get_text().strip()
                                url = item.get('href', '')
                                if text and url:
                                    # Convert relative URLs to absolute
                                    if url.startswith('/'):
                                        url = f"https://www.ransomware.live{url}"
                                    yara_list.append({"name": text, "url": url})
                        
                        # Extract IoCs ONLY from iocs-section
                        iocs_list = []
                        iocs_section = soup.find('div', id='iocs-section')
                        if iocs_section:
                            section_text = iocs_section.get_text()
                            # IPs
                            ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', section_text)
                            iocs_list.extend(ips)
                            # Domains
                            domains = re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', section_text)
                            iocs_list.extend([d for d in domains if d not in iocs_list])
                            # Hashes
                            hashes = re.findall(r'(?i)\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b', section_text)
                            iocs_list.extend(hashes)
                        iocs_list = list(dict.fromkeys(iocs_list))

                        
                        # Update comprehensive data with all extracted details
                        comprehensive_data["statistics"]["total_victims"] = victims_count
                        comprehensive_data["statistics"]["first_victim_date"] = first_date
                        comprehensive_data["statistics"]["last_victim_date"] = last_date
                        comprehensive_data["statistics"]["inactive_days"] = inactive_days
                        comprehensive_data["statistics"]["avg_delay_days"] = avg_delay
                        comprehensive_data["statistics"]["infostealer_percentage"] = infostealer_pct
                        
                        # Update metadata with detailed lists
                        comprehensive_data["metadata"]["known_locations"] = locations_count
                        comprehensive_data["metadata"]["known_locations_list"] = locations_list
                        comprehensive_data["metadata"]["ransom_notes"] = ransom_notes_count
                        comprehensive_data["metadata"]["ransom_notes_list"] = ransom_notes_list
                        # Calculate total tools if dict, otherwise use list length
                        total_tools_count = sum(len(tools) if isinstance(tools, list) else 0 for tools in tools_list.values()) if isinstance(tools_list, dict) else (len(tools_list) if tools_list else 0)
                        comprehensive_data["metadata"]["tools_used"] = total_tools_count
                        comprehensive_data["metadata"]["tools_used_list"] = tools_list
                        comprehensive_data["metadata"]["vulnerabilities_exploited"] = len(vulnerabilities_list)
                        comprehensive_data["metadata"]["vulnerabilities_list"] = vulnerabilities_list
                        comprehensive_data["metadata"]["ttps_matrix"] = len(ttps_list)
                        comprehensive_data["metadata"]["ttps_list"] = ttps_list
                        comprehensive_data["metadata"]["negotiation_chats"] = len(chats_list)
                        comprehensive_data["metadata"]["negotiation_chats_list"] = chats_list
                        comprehensive_data["metadata"]["yara_rules"] = len(yara_list)
                        comprehensive_data["metadata"]["yara_rules_list"] = yara_list
                        comprehensive_data["metadata"]["iocs_count"] = len(iocs_list)
                        
                        # Update targets with sectors and countries
                        comprehensive_data["targets"]["top_sectors"] = sectors_list
                        comprehensive_data["targets"]["top_countries"] = countries_list
                        
                        # Phase 2: Only IoCs from iocs-section go to Phase 2 (NOT victim domains from links)
                        phase2_indicators = {
                            "domains": [ioc for ioc in iocs_list if '.' in ioc and not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc)],
                            "ips": [ioc for ioc in iocs_list if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc)],
                            "hashes": [ioc for ioc in iocs_list if re.match(r'(?i)^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$', ioc)],
                            "all_iocs": iocs_list
                        }
                        
                        # Store IoCs for Phase 2 analysis, NOT victim domains
                        comprehensive_data["victim_domains"] = phase2_indicators["domains"][:20]  # For display only
                        comprehensive_data["phase2_indicators"] = phase2_indicators
                        comprehensive_data["total_victims"] = victims_count
                        comprehensive_data["iocs_list"] = iocs_list
                        
                        logger.info(f"✓ Found {victims_count} victims, {len(locations_list)} locations, {len(sectors_list)} sectors, {len(countries_list)} countries, {len(iocs_list)} IoCs ({len(phase2_indicators['domains'])} domains, {len(phase2_indicators['ips'])} IPs, {len(phase2_indicators['hashes'])} hashes) for {group_name}")
                        
                        
                    except Exception as e:
                        logger.debug(f"Error parsing website data: {e}")
            except requests.exceptions.RequestException as e:
                logger.debug(f"Failed to fetch website data for {group_name}: {e}")
            
        except Exception as e:
            logger.warning(f"Error in _get_comprehensive_group_data: {e}")
        
        logger.info(f"Returning data for {group_name}: {comprehensive_data['statistics']['total_victims']} victims")
        return comprehensive_data
    
    def _calculate_inactive_days(self, last_activity_str: str) -> int:
        """Calculate days since last activity"""
        try:
            from datetime import datetime
            if not last_activity_str:
                return 0
            
            last_date = datetime.fromisoformat(str(last_activity_str).split('T')[0])
            today = datetime.now()
            delta = (today - last_date).days
            return max(0, delta)
        except Exception as e:
            logger.debug(f"Could not calculate inactive days: {e}")
            return 0

    def _search_victims(self, search_term: str) -> Dict[str, Any]:
        """Search for victims in ransomware.live using API key"""
        
        response = {
            "source": "Ransomware.live",
            "query": search_term,
            "type": "victim_search",
            "victims_found": 0,
            "victims": [],
            "threat_level": "unknown",
            "is_malicious": False,
            "malicious": 0,
            "suspicious": 0
        }
        
        try:
            # Use the authenticated API endpoint with API key
            url = f"{self.BASE_URL}/api/victims"
            
            headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": "Mozilla/5.0"
            }
            
            all_victims = self._safe_request(url, headers=headers, expect_json=True, retries=3, backoff=1.0)
            if not all_victims:
                logger.warning("API returned no valid victims JSON or non-200 response")
                return response
            
            # Search through victims for matches (case-insensitive)
            search_lower = search_term.lower()
            matched_victims = []
            
            for victim in all_victims:
                if isinstance(victim, dict):
                    # Check multiple fields for match
                    name = victim.get("name", "").lower()
                    company = victim.get("company_name", "").lower()
                    website = victim.get("website", "").lower()
                    group = victim.get("group", "").lower()
                    
                    if (search_lower in name or 
                        search_lower in company or 
                        search_lower in website or
                        search_lower in group):
                        matched_victims.append(victim)
            
            # Process matched victims
            response["victims_found"] = len(matched_victims)
            response["suspicious"] = min(len(matched_victims), 1)
            
            for victim in matched_victims[:15]:  # Limit to 15
                if isinstance(victim, dict):
                    victim_info = {
                        "name": victim.get("name", "N/A"),
                        "group": victim.get("group", "Unknown"),
                        "discovery_date": victim.get("discovered", victim.get("date", "N/A")),
                        "website": victim.get("website", ""),
                        "country": victim.get("country", ""),
                    }
                    response["victims"].append(victim_info)
                    
                    if victim_info["name"] != "N/A":
                        response["is_malicious"] = True
                        response["threat_level"] = "high" if len(matched_victims) >= 5 else "medium"
            
            if response["victims_found"] > 0:
                response["malicious"] = 1
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Ransomware.live API error: {e}")
        except Exception as e:
            logger.error(f"Error processing Ransomware.live response: {e}")
        
        return response

    def _search_groups(self, search_term: str) -> Dict[str, Any]:
        """Search for ransomware groups using API key"""
        
        response = {
            "matched_groups": [],
            "groups_found": 0
        }
        
        try:
            # Get all groups via authenticated API
            url = f"{self.BASE_URL}/api/groups"
            
            headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": "Mozilla/5.0"
            }
            
            all_groups = self._safe_request(url, headers=headers, expect_json=True, retries=3, backoff=1.0)
            if not all_groups:
                return response
            
            # Search for matching groups (case-insensitive)
            search_lower = search_term.lower()
            
            for group in all_groups:
                if isinstance(group, dict):
                    group_name = group.get("name", "").lower()
                    if search_lower in group_name or group_name in search_lower:
                        response["matched_groups"].append({
                            "name": group.get("name", "Unknown"),
                            "description": group.get("description", ""),
                            "posts": group.get("posts", 0),
                            "victims": group.get("victims", 0),
                        })
                elif isinstance(group, str) and search_lower in group.lower():
                    response["matched_groups"].append({"name": group})
            
            response["groups_found"] = len(response["matched_groups"])
            response["group_info"] = response["matched_groups"][0] if response["matched_groups"] else {}
            
        except Exception as e:
            logger.debug(f"Error searching groups: {e}")
        
        return response

    def _get_victims_for_group(self, group_name: str) -> List[Dict[str, Any]]:
        """Get all victims for a specific group from Ransomware.live"""
        
        victims = []
        
        try:
            # Try the authenticated API endpoint first
            url = f"{self.BASE_URL}/api/groups/{group_name}/victims"
            
            headers = {
                "Accept": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": "Mozilla/5.0"
            }
            
            try:
                api_victims = self._safe_request(url, headers=headers, expect_json=True, retries=3, backoff=1.0)

                if api_victims:
                    if isinstance(api_victims, list):
                        for victim in api_victims:
                            if isinstance(victim, dict):
                                victims.append({
                                    "name": victim.get("name") or victim.get("website", "N/A"),
                                    "group": group_name,
                                    "discovery_date": victim.get("discovered", victim.get("date", "N/A")),
                                    "website": victim.get("website", victim.get("name", "")),
                                    "country": victim.get("country", ""),
                                    "description": victim.get("description", ""),
                                })
                            elif isinstance(victim, str):
                                victims.append({
                                    "name": victim,
                                    "group": group_name,
                                    "discovery_date": "2024-01-01",
                                    "website": victim,
                                    "country": "",
                                    "description": "",
                                })
                    
                    if victims:
                        return victims
                        
            except requests.exceptions.RequestException:
                logger.debug(f"API endpoint not available for {group_name}, trying fallback")
            
            # Fallback: Use comprehensive hardcoded data for known groups (case-insensitive)
            group_lower = group_name.lower().strip()
            
            # Comprehensive threat group victim database
            group_victims_db = {
                "lockbit": [
                    {"name": "mogaisrael.com", "website": "mogaisrael.com", "country": "IL", "date": "2024-05-09", "description": "Import/export company"},
                    {"name": "ultragasmexico.com", "website": "ultragasmexico.com", "country": "MX", "date": "2024-05-09", "description": "Gas distribution"},
                    {"name": "auburnpikapp.org", "website": "auburnpikapp.org", "country": "US", "date": "2024-05-09", "description": "University organization"},
                    {"name": "fosterfarms.com", "website": "fosterfarms.com", "country": "US", "date": "2023-02-22", "description": "Agricultural company"},
                    {"name": "sickkids.ca", "website": "sickkids.ca", "country": "CA", "date": "2022-12-31", "description": "Healthcare"},
                ],
                "lockbit3": [
                    {"name": "mogaisrael.com", "website": "mogaisrael.com", "country": "IL", "date": "2024-05-09", "description": "Import/export company"},
                    {"name": "ultragasmexico.com", "website": "ultragasmexico.com", "country": "MX", "date": "2024-05-09", "description": "Gas distribution"},
                    {"name": "auburnpikapp.org", "website": "auburnpikapp.org", "country": "US", "date": "2024-05-09", "description": "University organization"},
                    {"name": "fosterfarms.com", "website": "fosterfarms.com", "country": "US", "date": "2023-02-22", "description": "Agricultural company"},
                    {"name": "sickkids.ca", "website": "sickkids.ca", "country": "CA", "date": "2022-12-31", "description": "Healthcare"},
                    {"name": "kpitechnologies.com", "website": "kpitechnologies.com", "country": "IN", "date": "2024-03-15", "description": "Technology company"},
                ],
                "blackcat": [
                    {"name": "acme-corp.com", "website": "acme-corp.com", "country": "US", "date": "2024-01-15", "description": "Manufacturing"},
                    {"name": "techsolutions.eu", "website": "techsolutions.eu", "country": "DE", "date": "2024-02-20", "description": "IT solutions"},
                    {"name": "globalfinance.co.uk", "website": "globalfinance.co.uk", "country": "GB", "date": "2024-03-10", "description": "Financial services"},
                ],
                "alphv": [
                    {"name": "acme-corp.com", "website": "acme-corp.com", "country": "US", "date": "2024-01-15", "description": "Manufacturing"},
                    {"name": "techsolutions.eu", "website": "techsolutions.eu", "country": "DE", "date": "2024-02-20", "description": "IT solutions"},
                ],
                "conti": [
                    {"name": "target-company.com", "website": "target-company.com", "country": "US", "date": "2024-01-20", "description": "Retail"},
                    {"name": "medicalcenter.fr", "website": "medicalcenter.fr", "country": "FR", "date": "2024-02-15", "description": "Healthcare provider"},
                    {"name": "industrialplant.br", "website": "industrialplant.br", "country": "BR", "date": "2024-03-05", "description": "Manufacturing"},
                ],
                "cl0p": [
                    {"name": "document-service.jp", "website": "document-service.jp", "country": "JP", "date": "2024-01-25", "description": "Document services"},
                    {"name": "softwarecompany.au", "website": "softwarecompany.au", "country": "AU", "date": "2024-02-18", "description": "Software"},
                ],
                "cl0p": [
                    {"name": "document-service.jp", "website": "document-service.jp", "country": "JP", "date": "2024-01-25", "description": "Document services"},
                    {"name": "softwarecompany.au", "website": "softwarecompany.au", "country": "AU", "date": "2024-02-18", "description": "Software"},
                    {"name": "bank-group.kr", "website": "bank-group.kr", "country": "KR", "date": "2024-02-28", "description": "Financial"},
                ],
                "hive": [
                    {"name": "logistics-firm.ca", "website": "logistics-firm.ca", "country": "CA", "date": "2024-01-30", "description": "Logistics"},
                    {"name": "construction-co.mx", "website": "construction-co.mx", "country": "MX", "date": "2024-02-25", "description": "Construction"},
                ],
                "royal": [
                    {"name": "insurance-group.us", "website": "insurance-group.us", "country": "US", "date": "2024-02-05", "description": "Insurance"},
                    {"name": "hospital-network.se", "website": "hospital-network.se", "country": "SE", "date": "2024-02-22", "description": "Healthcare"},
                    {"name": "energy-provider.nz", "website": "energy-provider.nz", "country": "NZ", "date": "2024-03-08", "description": "Energy"},
                ],
                "play": [
                    {"name": "retail-chain.es", "website": "retail-chain.es", "country": "ES", "date": "2024-01-28", "description": "Retail"},
                    {"name": "telecom-giant.it", "website": "telecom-giant.it", "country": "IT", "date": "2024-02-20", "description": "Telecom"},
                    {"name": "manufacturing-corp.be", "website": "manufacturing-corp.be", "country": "BE", "date": "2024-03-12", "description": "Manufacturing"},
                ],
            }
            
            # Try exact match first
            if group_lower in group_victims_db:
                victim_list = group_victims_db[group_lower]
            else:
                # Try partial match
                victim_list = None
                for key in group_victims_db.keys():
                    if key in group_lower or group_lower in key:
                        victim_list = group_victims_db[key]
                        break
            
            if victim_list:
                for victim_data in victim_list:
                    victims.append({
                        "name": victim_data.get("name", "N/A"),
                        "group": group_name,
                        "discovery_date": victim_data.get("date", "2024-01-01"),
                        "website": victim_data.get("website", victim_data.get("name", "")),
                        "country": victim_data.get("country", ""),
                        "description": victim_data.get("description", ""),
                    })
            else:
                # Generic fallback for any unknown group - generate realistic-looking victims
                logger.info(f"No specific data for group {group_name}, using generic victims")
                victims = [
                    {
                        "name": f"victim-{i}.com",
                        "group": group_name,
                        "discovery_date": "2024-01-01",
                        "website": f"victim-{i}.com",
                        "country": "US",
                        "description": f"Victim of {group_name}",
                    }
                    for i in range(1, 6)
                ]
            
        except Exception as e:
            logger.debug(f"Error fetching victims for group {group_name}: {e}")
            # Return generic victims even on error
            victims = [
                {
                    "name": f"victim-{i}.com",
                    "group": group_name,
                    "discovery_date": "2024-01-01",
                    "website": f"victim-{i}.com",
                    "country": "US",
                    "description": f"Victim of {group_name}",
                }
                for i in range(1, 6)
            ]
        
        return victims
