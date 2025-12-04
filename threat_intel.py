"""
Threat Intelligence Feed

Provides realistic threat intelligence data including threat levels,
vulnerability status, and industry alerts relevant to financial institutions.
"""

from typing import Dict, List, Any
import random
from datetime import datetime, timedelta


def get_current_threat_level() -> Dict[str, Any]:
    """
    Get current threat intelligence and assessment
    
    Returns:
        Dictionary with threat levels, active threats, and recommended posture
    """
    # Simulate realistic threat landscape
    threat_levels = ["LOW", "MODERATE", "ELEVATED", "HIGH", "CRITICAL"]
    
    # Financial sector typically faces elevated threats
    overall_level = random.choice(["MODERATE", "ELEVATED", "ELEVATED", "HIGH"])
    financial_level = random.choice(["ELEVATED", "HIGH", "HIGH"])
    
    active_threats = []
    
    # Ransomware threats - always present in financial sector
    if random.random() > 0.3:
        active_threats.append({
            "threat_id": "TH-2024-001",
            "name": "LockBit 3.0 Ransomware",
            "targeting": "Financial institutions, payment processors",
            "severity": "CRITICAL",
            "ttps": ["T1486-Data Encrypted for Impact", "T1490-Inhibit System Recovery", "T1048-Exfiltration Over C2"]
        })
    
    # Nation-state APT activity
    if random.random() > 0.4:
        active_threats.append({
            "threat_id": "TH-2024-002",
            "name": "APT38 (Lazarus Group)",
            "targeting": "SWIFT infrastructure, international banks",
            "severity": "HIGH",
            "ttps": ["T1078-Valid Accounts", "T1005-Data from Local System", "T1020-Automated Exfiltration"]
        })
    
    # DDoS campaigns
    if random.random() > 0.5:
        active_threats.append({
            "threat_id": "TH-2024-003",
            "name": "Distributed DDoS Campaign",
            "targeting": "Online banking platforms, payment gateways",
            "severity": "MODERATE",
            "ttps": ["T1498-Network Denial of Service", "T1499-Endpoint Denial of Service"]
        })
    
    # Phishing/BEC
    active_threats.append({
        "threat_id": "TH-2024-004",
        "name": "Business Email Compromise (BEC)",
        "targeting": "Finance departments, wire transfer operations",
        "severity": "HIGH",
        "ttps": ["T1566-Phishing", "T1534-Internal Spearphishing", "T1114-Email Collection"]
    })
    
    # Supply chain threats
    if random.random() > 0.6:
        active_threats.append({
            "threat_id": "TH-2024-005",
            "name": "Third-Party Software Supply Chain Compromise",
            "targeting": "Financial software vendors, cloud service providers",
            "severity": "HIGH",
            "ttps": ["T1195-Supply Chain Compromise", "T1072-Software Deployment Tools"]
        })
    
    # Determine recommended posture based on threat level
    posture_map = {
        "LOW": "NORMAL - Standard security controls",
        "MODERATE": "VIGILANT - Enhanced monitoring recommended",
        "ELEVATED": "HEIGHTENED - Increase security monitoring, review access controls",
        "HIGH": "GUARDED - Implement additional controls, prepare incident response",
        "CRITICAL": "SEVERE - Maximum security posture, activate crisis management"
    }
    
    return {
        "overall_threat_level": overall_level,
        "financial_sector_threat_level": financial_level,
        "active_threats": active_threats,
        "threat_count": len(active_threats),
        "recommended_posture": posture_map.get(financial_level, "VIGILANT"),
        "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    }


def get_vulnerability_status() -> Dict[str, Any]:
    """
    Get current vulnerability and patch compliance status
    
    Returns:
        Dictionary with vulnerability counts, patch compliance, and exposure score
    """
    # Simulate realistic vulnerability landscape
    critical_vulns = random.randint(0, 3)
    high_vulns = random.randint(2, 8)
    medium_vulns = random.randint(5, 15)
    low_vulns = random.randint(10, 25)
    
    # Patch compliance (higher is better)
    patch_compliance = random.uniform(85, 98)
    
    # Calculate exposure score (0-100, lower is better)
    exposure_score = (
        (critical_vulns * 25) + 
        (high_vulns * 10) + 
        (medium_vulns * 3) + 
        (low_vulns * 1)
    )
    exposure_score = min(100, exposure_score)
    
    vulnerability_data = {
        "vulnerability_summary": {
            "critical": critical_vulns,
            "high": high_vulns,
            "medium": medium_vulns,
            "low": low_vulns,
            "total": critical_vulns + high_vulns + medium_vulns + low_vulns
        },
        "patch_compliance_percentage": round(patch_compliance, 1),
        "exposure_score": round(exposure_score, 1),
        "exposure_rating": _get_exposure_rating(exposure_score),
        "critical_cves": [],
        "remediation_priority": "URGENT" if critical_vulns > 0 else "HIGH" if high_vulns > 3 else "MODERATE"
    }
    
    # Add specific CVEs if critical vulnerabilities exist
    if critical_vulns > 0:
        vulnerability_data["critical_cves"] = [
            {
                "cve_id": "CVE-2024-1234",
                "component": "OpenSSL 3.0.x",
                "severity": "CRITICAL (CVSS 9.8)",
                "description": "Remote code execution in TLS handshake"
            }
        ]
    
    return vulnerability_data


def _get_exposure_rating(score: float) -> str:
    """Get human-readable exposure rating"""
    if score < 20:
        return "MINIMAL"
    elif score < 40:
        return "LOW"
    elif score < 60:
        return "MODERATE"
    elif score < 80:
        return "HIGH"
    else:
        return "CRITICAL"


def get_industry_alerts() -> Dict[str, List[Dict[str, Any]]]:
    """
    Get recent industry security alerts from FS-ISAC and CISA
    
    Returns:
        Dictionary with recent alerts from financial sector information sharing organizations
    """
    # Generate realistic looking alerts
    today = datetime.now()
    
    alerts = {
        "fs_isac_alerts": [
            {
                "alert_id": "FS-ISAC-2024-001",
                "date": (today - timedelta(days=1)).strftime("%Y-%m-%d"),
                "title": "Increased Ransomware Activity Targeting Regional Banks",
                "severity": "HIGH",
                "summary": "Multiple ransomware groups observed targeting regional banking institutions with spear-phishing campaigns.",
                "recommendation": "Enhance email security controls, conduct user awareness training"
            },
            {
                "alert_id": "FS-ISAC-2024-002",
                "date": (today - timedelta(days=3)).strftime("%Y-%m-%d"),
                "title": "SWIFT Network Reconnaissance Activity Detected",
                "severity": "CRITICAL",
                "summary": "Advanced persistent threat actors conducting reconnaissance on SWIFT messaging infrastructure.",
                "recommendation": "Review SWIFT access controls, enable enhanced monitoring"
            },
            {
                "alert_id": "FS-ISAC-2024-003",
                "date": (today - timedelta(days=5)).strftime("%Y-%m-%d"),
                "title": "Third-Party Vendor Compromise Affecting Financial Services",
                "severity": "MODERATE",
                "summary": "Supply chain compromise at major financial software vendor may affect downstream customers.",
                "recommendation": "Conduct vendor risk assessment, review third-party access"
            }
        ],
        "cisa_alerts": [
            {
                "alert_id": "AA24-001A",
                "date": (today - timedelta(days=2)).strftime("%Y-%m-%d"),
                "title": "CISA Alert: Critical Vulnerabilities in Financial Sector Software",
                "severity": "CRITICAL",
                "summary": "Multiple critical vulnerabilities identified in widely-used financial services applications.",
                "recommendation": "Apply patches immediately, implement workarounds if patches unavailable"
            },
            {
                "alert_id": "AA24-002A",
                "date": (today - timedelta(days=7)).strftime("%Y-%m-%d"),
                "title": "Nation-State Actors Targeting Financial Institutions",
                "severity": "HIGH",
                "summary": "Foreign intelligence services actively targeting U.S. financial institutions for espionage and disruption.",
                "recommendation": "Enhance network segmentation, review authentication mechanisms"
            }
        ],
        "last_updated": today.strftime("%Y-%m-%d %H:%M:%S UTC")
    }
    
    return alerts
