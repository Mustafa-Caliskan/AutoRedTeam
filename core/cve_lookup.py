"""
AutoRedTeam - Live CVE Intelligence Lookup.

Queries the NVD (National Vulnerability Database) CVE API for the latest
known vulnerabilities affecting a given product/version. This gives the
assessment model access to up-to-date CVE information beyond its training
cutoff.

DESIGN PRINCIPLE:
  - This is a LOOKUP-ONLY tool. It only fetches CVE metadata (descriptions,
    CVSS scores, references). It NEVER runs or suggests any exploit.
  - It does not target any host directly; it queries the public NVD API.
"""

import json
import logging
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RESULTS = 3
TIMEOUT = 20


def _fetch_nvd(query: str) -> List[Dict[str, Any]]:
    """
    Queries the NVD CVE API for a product/version keyword.
    Returns a list of CVE records (id, description, cvss, published date).
    """
    params = urllib.parse.urlencode({
        "keywordSearch": query,
        "resultsPerPage": MAX_RESULTS,
    })
    url = f"{NVD_API_URL}?{params}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AutoRedTeam/1.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        logger.warning(f"NVD API request failed: {e}")
        return []

    vulns = data.get("vulnerabilities", [])
    results: List[Dict[str, Any]] = []
    for v in vulns[:MAX_RESULTS]:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        desc = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        metrics = cve.get("metrics", {})
        cvss = ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                cvss = str(cvss_data.get("baseScore", ""))
                break
        results.append({
            "id": cve_id,
            "description": desc[:300],
            "cvss": cvss,
            "published": cve.get("published", ""),
        })
    return results


def lookup_cve(service_name: str, version: str = "") -> Dict[str, Any]:
    """
    Looks up known CVEs for a service/version via the NVD API.
    Returns a structured result with the top CVEs and a summary.
    """
    query = f"{service_name} {version}".strip()
    cves = _fetch_nvd(query)

    if not cves:
        return {
            "status": "NO_RESULTS",
            "query": query,
            "message": f"NVD'de '{query}' için kayıtlı CVE bulunamadı.",
            "cves": [],
        }

    return {
        "status": "FOUND",
        "query": query,
        "message": f"NVD'de '{query}' için {len(cves)} CVE kaydı bulundu.",
        "cves": cves,
    }
