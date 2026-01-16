"""
URLhaus API integration
"""

import logging
from typing import Dict, Any
from .base import BaseAPIClient

logger = logging.getLogger(__name__)


class URLHausAPI(BaseAPIClient):
    """URLhaus API client (no auth required)"""

    BASE_URL = "https://urlhaus-api.abuse.ch/v1/"

    def __init__(self, api_key: str = None, timeout: int = 30):
        """Initialize - URLhaus doesn't require API key"""
        self.api_key = api_key
        self.timeout = timeout
        self.session = self._create_session()

    def analyze(self, observable: str) -> Dict[str, Any]:
        """
        Analyze URL using URLhaus API
        
        Args:
            observable: URL
            
        Returns:
            Analysis results
        """
        if not self._is_valid_url(observable) and not self._is_valid_domain(observable):
            return {"error": "Invalid URL or domain"}
        
        if self._is_valid_url(observable):
            return self._query_url(observable)
        else:
            return self._query_domain(observable)

    def _query_url(self, url: str) -> Dict[str, Any]:
        """Query URL from URLhaus"""
        data = {"url": url}
        api_url = f"{self.BASE_URL}url"
        
        result = self._make_request(api_url, method="POST", json_data=data)
        
        if "error" in result:
            return result
        
        if result.get("query_status") != "ok":
            return {
                "source": "URLhaus",
                "type": "url",
                "observable": url,
                "status": "not_found",
            }
        
        query_result = result.get("result", {})
        
        return {
            "source": "URLhaus",
            "type": "url",
            "observable": url,
            "status": query_result.get("url_status"),
            "threat": query_result.get("threat"),
            "tags": query_result.get("tags", []),
            "date_added": query_result.get("date_added"),
            "last_submitted": query_result.get("last_submitted"),
            "submission_count": query_result.get("submission_count"),
            "payload": self._extract_payloads(query_result.get("payloads", [])),
            "raw_data": result,
        }

    def _query_domain(self, domain: str) -> Dict[str, Any]:
        """Query domain from URLhaus"""
        data = {"domain": domain}
        api_url = f"{self.BASE_URL}urls/filter"
        
        result = self._make_request(api_url, method="POST", json_data=data)
        
        if "error" in result:
            return result
        
        if result.get("query_status") != "ok":
            return {
                "source": "URLhaus",
                "type": "domain",
                "observable": domain,
                "status": "not_found",
            }
        
        urls = result.get("urls", [])
        
        return {
            "source": "URLhaus",
            "type": "domain",
            "observable": domain,
            "url_count": len(urls),
            "urls": [self._format_url_entry(u) for u in urls[:10]],  # Limit to 10
            "raw_data": result,
        }

    @staticmethod
    def _extract_payloads(payloads: list) -> list:
        """Extract payload information"""
        formatted = []
        for payload in payloads[:3]:  # Limit to 3
            formatted.append({
                "type": payload.get("type"),
                "signature": payload.get("signature", "")[:100],
                "url": payload.get("url", "")[:100],
            })
        return formatted

    @staticmethod
    def _format_url_entry(url_entry: Dict) -> Dict:
        """Format URL entry"""
        return {
            "url": url_entry.get("url", "")[:100],
            "status": url_entry.get("url_status"),
            "threat": url_entry.get("threat"),
            "tags": url_entry.get("tags", []),
            "date_added": url_entry.get("date_added"),
        }
