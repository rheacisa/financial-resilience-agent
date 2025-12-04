"""
Incident Response Playbooks

Provides detailed incident response procedures for various scenarios
including ransomware, liquidity crisis, disaster recovery, and data breaches.
"""

from typing import Dict, List, Any, Optional


# Comprehensive playbook database
PLAYBOOKS = {
    "ransomware": {
        "name": "Ransomware Incident Response",
        "category": "CYBER_INCIDENT",
        "severity": "CRITICAL",
        "estimated_duration": "48-72 hours",
        "steps": [
            {
                "step": 1,
                "phase": "ISOLATE",
                "action": "Immediately isolate affected systems from network",
                "duration": "15 minutes",
                "owner": "Security Operations Center"
            },
            {
                "step": 2,
                "phase": "PRESERVE",
                "action": "Preserve forensic evidence and system logs",
                "duration": "30 minutes",
                "owner": "Forensics Team"
            },
            {
                "step": 3,
                "phase": "ASSESS",
                "action": "Assess scope of encryption and identify ransomware variant",
                "duration": "2-4 hours",
                "owner": "Incident Response Team"
            },
            {
                "step": 4,
                "phase": "ACTIVATE",
                "action": "Activate disaster recovery procedures, restore from clean backups",
                "duration": "4-8 hours",
                "owner": "Infrastructure Team"
            },
            {
                "step": 5,
                "phase": "NOTIFY",
                "action": "Notify regulators and law enforcement within required timeframes",
                "duration": "1-2 hours",
                "owner": "Legal/Compliance"
            },
            {
                "step": 6,
                "phase": "RECOVER",
                "action": "Systematically restore services, validate data integrity",
                "duration": "12-24 hours",
                "owner": "Infrastructure Team"
            },
            {
                "step": 7,
                "phase": "HARDEN",
                "action": "Apply security patches, enhance monitoring, review access controls",
                "duration": "8-12 hours",
                "owner": "Security Team"
            },
            {
                "step": 8,
                "phase": "REVIEW",
                "action": "Conduct post-incident review, update playbooks and controls",
                "duration": "4-6 hours",
                "owner": "Incident Commander"
            }
        ],
        "regulatory_notifications": [
            {
                "regulator": "OCC - Office of the Comptroller of the Currency",
                "timeframe": "Immediately (within hours of discovery)",
                "requirement": "Report significant cyber incidents"
            },
            {
                "regulator": "FDIC - Federal Deposit Insurance Corporation",
                "timeframe": "Immediately for significant disruptions",
                "requirement": "Notification of computer security incidents"
            },
            {
                "regulator": "State Banking Regulators",
                "timeframe": "As soon as possible, typically within 24-48 hours",
                "requirement": "Cyber incident reporting per state requirements"
            },
            {
                "regulator": "FBI Internet Crime Complaint Center (IC3)",
                "timeframe": "As soon as practical",
                "requirement": "File complaint for ransomware incidents"
            }
        ],
        "recovery_metrics": {
            "rto": "4 hours (Recovery Time Objective)",
            "rpo": "1 hour (Recovery Point Objective)",
            "expected_uptime_recovery": "95%+ within 24 hours"
        },
        "do_not": [
            "Do NOT pay ransom without executive approval and legal consultation",
            "Do NOT power off systems without preserving volatile memory",
            "Do NOT restore from backups until malware is fully eradicated"
        ]
    },
    
    "liquidity_crisis": {
        "name": "Liquidity Crisis Management",
        "category": "FINANCIAL_STRESS",
        "severity": "CRITICAL",
        "estimated_duration": "Ongoing until resolved",
        "steps": [
            {
                "step": 1,
                "phase": "ASSESS",
                "action": "Assess current liquidity position and immediate obligations",
                "duration": "1 hour",
                "owner": "Treasury Department"
            },
            {
                "step": 2,
                "phase": "ACTIVATE",
                "action": "Activate liquidity contingency funding plan",
                "duration": "2 hours",
                "owner": "CFO/Treasurer"
            },
            {
                "step": 3,
                "phase": "SOURCE",
                "action": "Identify and activate emergency funding sources (Fed discount window, etc.)",
                "duration": "4-8 hours",
                "owner": "Treasury Department"
            },
            {
                "step": 4,
                "phase": "NOTIFY",
                "action": "Notify regulators of liquidity stress condition",
                "duration": "1-2 hours",
                "owner": "Legal/Compliance"
            },
            {
                "step": 5,
                "phase": "COMMUNICATE",
                "action": "Prepare stakeholder communications (board, customers, investors)",
                "duration": "2-4 hours",
                "owner": "Communications/IR"
            },
            {
                "step": 6,
                "phase": "STABILIZE",
                "action": "Execute funding plan, monitor inflows/outflows continuously",
                "duration": "Ongoing",
                "owner": "Treasury Operations"
            }
        ],
        "regulatory_notifications": [
            {
                "regulator": "Federal Reserve",
                "timeframe": "Immediately",
                "requirement": "Notify before using discount window or emergency facilities"
            },
            {
                "regulator": "OCC/Primary Regulator",
                "timeframe": "Immediately upon activation of contingency funding",
                "requirement": "Report material liquidity stress conditions"
            }
        ],
        "recovery_metrics": {
            "target_lcr": "Restore to >100% within 72 hours",
            "funding_sources": "Diversify across 3+ sources",
            "monitoring_frequency": "Real-time during crisis"
        },
        "do_not": [
            "Do NOT delay regulatory notification",
            "Do NOT communicate externally without legal review",
            "Do NOT access emergency funding without proper authorization"
        ]
    },
    
    "disaster_recovery": {
        "name": "Disaster Recovery Activation",
        "category": "BUSINESS_CONTINUITY",
        "severity": "HIGH",
        "estimated_duration": "8-24 hours",
        "steps": [
            {
                "step": 1,
                "phase": "DECLARE",
                "action": "Declare disaster, activate crisis management team",
                "duration": "30 minutes",
                "owner": "Incident Commander"
            },
            {
                "step": 2,
                "phase": "ASSESS",
                "action": "Assess impact to primary data center and critical systems",
                "duration": "1 hour",
                "owner": "Infrastructure Team"
            },
            {
                "step": 3,
                "phase": "ACTIVATE",
                "action": "Activate secondary data center and failover procedures",
                "duration": "2-4 hours",
                "owner": "Infrastructure Team"
            },
            {
                "step": 4,
                "phase": "RESTORE",
                "action": "Restore critical services (priorities: payments, online banking, core systems)",
                "duration": "4-8 hours",
                "owner": "Application Teams"
            },
            {
                "step": 5,
                "phase": "VERIFY",
                "action": "Verify data integrity and system functionality",
                "duration": "2-4 hours",
                "owner": "QA/Testing Team"
            },
            {
                "step": 6,
                "phase": "COMMUNICATE",
                "action": "Communicate status to regulators, customers, and stakeholders",
                "duration": "1-2 hours",
                "owner": "Communications"
            },
            {
                "step": 7,
                "phase": "STABILIZE",
                "action": "Monitor systems, prepare for failback when primary site available",
                "duration": "Ongoing",
                "owner": "Operations Team"
            }
        ],
        "recovery_metrics": {
            "rto": "4 hours for Tier 1 systems",
            "rpo": "1 hour maximum data loss",
            "success_criteria": "All critical systems operational in DR environment"
        },
        "do_not": [
            "Do NOT attempt failback until primary site fully validated",
            "Do NOT skip data integrity verification steps",
            "Do NOT assume DR systems are ready without testing"
        ]
    },
    
    "data_breach": {
        "name": "Data Breach Response",
        "category": "CYBER_INCIDENT",
        "severity": "CRITICAL",
        "estimated_duration": "72+ hours",
        "steps": [
            {
                "step": 1,
                "phase": "CONTAIN",
                "action": "Contain breach, prevent further data exfiltration",
                "duration": "1-2 hours",
                "owner": "Security Operations"
            },
            {
                "step": 2,
                "phase": "ASSESS",
                "action": "Assess scope: what data, how many records, sensitivity level",
                "duration": "4-8 hours",
                "owner": "Forensics Team"
            },
            {
                "step": 3,
                "phase": "NOTIFY_INTERNAL",
                "action": "Notify executive leadership, legal, compliance, and PR teams",
                "duration": "1 hour",
                "owner": "Incident Commander"
            },
            {
                "step": 4,
                "phase": "LEGAL_REVIEW",
                "action": "Engage external legal counsel for breach response guidance",
                "duration": "2-4 hours",
                "owner": "General Counsel"
            },
            {
                "step": 5,
                "phase": "REGULATORY_NOTIFY",
                "action": "File regulatory notifications within required timeframes",
                "duration": "Varies by jurisdiction",
                "owner": "Legal/Compliance"
            },
            {
                "step": 6,
                "phase": "CUSTOMER_NOTIFY",
                "action": "Notify affected customers per regulatory requirements",
                "duration": "Varies by jurisdiction",
                "owner": "Communications/Legal"
            },
            {
                "step": 7,
                "phase": "REMEDIATE",
                "action": "Remediate vulnerability, enhance security controls",
                "duration": "Ongoing",
                "owner": "Security Team"
            },
            {
                "step": 8,
                "phase": "CREDIT_MONITORING",
                "action": "Offer credit monitoring services to affected individuals",
                "duration": "Ongoing",
                "owner": "Customer Service"
            }
        ],
        "regulatory_notifications": [
            {
                "regulator": "GDPR (if EU customers affected)",
                "timeframe": "72 hours of becoming aware",
                "requirement": "Notify supervisory authority of personal data breach"
            },
            {
                "regulator": "SEC (if material impact)",
                "timeframe": "4 business days",
                "requirement": "Report material cybersecurity incidents"
            },
            {
                "regulator": "State Attorneys General",
                "timeframe": "Varies by state (typically 30-90 days)",
                "requirement": "Notify residents of data breaches per state laws"
            },
            {
                "regulator": "Banking Regulators (OCC/FDIC)",
                "timeframe": "As soon as possible",
                "requirement": "Report data breaches affecting customer information"
            }
        ],
        "recovery_metrics": {
            "notification_compliance": "100% within regulatory deadlines",
            "remediation_target": "Close vulnerability within 30 days",
            "customer_trust_recovery": "Target 85%+ confidence within 6 months"
        },
        "do_not": [
            "Do NOT delay regulatory notifications to 'investigate further'",
            "Do NOT communicate externally before legal review",
            "Do NOT underestimate scope - verify thoroughly"
        ]
    }
}


def get_playbook(incident_type: str) -> Optional[Dict[str, Any]]:
    """
    Get incident response playbook for specified incident type
    
    Args:
        incident_type: Type of incident (ransomware, liquidity_crisis, disaster_recovery, data_breach)
    
    Returns:
        Playbook dictionary or None if not found
    """
    # Normalize incident type
    incident_type = incident_type.lower().replace(" ", "_").replace("-", "_")
    
    # Handle common variations
    type_mapping = {
        "ransom": "ransomware",
        "liquidity": "liquidity_crisis",
        "dr": "disaster_recovery",
        "disaster": "disaster_recovery",
        "breach": "data_breach",
        "data": "data_breach"
    }
    
    # Check direct match first
    if incident_type in PLAYBOOKS:
        return PLAYBOOKS[incident_type]
    
    # Check mapped variations
    for key, value in type_mapping.items():
        if key in incident_type:
            return PLAYBOOKS.get(value)
    
    # Return None if no match
    return None


def get_all_playbooks() -> Dict[str, Dict[str, Any]]:
    """
    Get all available incident response playbooks
    
    Returns:
        Dictionary of all playbooks
    """
    return PLAYBOOKS


def calculate_recovery_impact(playbook_name: str) -> Dict[str, Any]:
    """
    Calculate projected recovery impact for given playbook
    
    Args:
        playbook_name: Name of the playbook to analyze
    
    Returns:
        Dictionary with recovery projections and resource requirements
    """
    playbook = get_playbook(playbook_name)
    
    if not playbook:
        return {
            "error": f"Playbook not found: {playbook_name}",
            "available_playbooks": list(PLAYBOOKS.keys())
        }
    
    # Calculate total estimated duration
    total_hours = 0
    for step in playbook.get("steps", []):
        duration_str = step.get("duration", "1 hour")
        # Simple parsing - extract first number
        try:
            if "minutes" in duration_str:
                hours = float(duration_str.split()[0]) / 60
            elif "-" in duration_str:
                # Take average of range
                parts = duration_str.split("-")
                low = float(parts[0].strip())
                high = float(parts[1].split()[0].strip())
                hours = (low + high) / 2
            else:
                hours = float(duration_str.split()[0])
            total_hours += hours
        except (ValueError, IndexError):
            total_hours += 2  # Default to 2 hours if parsing fails
    
    # Calculate projected improvements based on playbook type
    improvements = {}
    cost_estimate_mm = 0.0
    
    if "ransomware" in playbook_name.lower():
        improvements = {
            "cyber_resilience_score": "+15 to +25 points",
            "system_uptime": "+10 to +20%",
            "customer_trust_index": "+5 to +10 points"
        }
        cost_estimate_mm = 2.5
    elif "liquidity" in playbook_name.lower():
        improvements = {
            "liquidity_coverage_ratio": "+20 to +40%",
            "capital_adequacy_ratio": "+1 to +3%"
        }
        cost_estimate_mm = 1.0
    elif "disaster" in playbook_name.lower():
        improvements = {
            "system_uptime": "+15 to +25%",
            "cyber_resilience_score": "+10 to +15 points"
        }
        cost_estimate_mm = 3.0
    elif "breach" in playbook_name.lower():
        improvements = {
            "customer_trust_index": "+10 to +20 points",
            "cyber_resilience_score": "+15 to +25 points"
        }
        cost_estimate_mm = 5.0
    
    return {
        "playbook_name": playbook.get("name"),
        "category": playbook.get("category"),
        "severity": playbook.get("severity"),
        "estimated_duration_hours": round(total_hours, 1),
        "total_steps": len(playbook.get("steps", [])),
        "projected_improvements": improvements,
        "estimated_cost_mm": cost_estimate_mm,
        "regulatory_notifications_required": len(playbook.get("regulatory_notifications", [])),
        "success_probability": "85-95%" if playbook.get("category") == "BUSINESS_CONTINUITY" else "75-90%",
        "resource_requirements": {
            "teams_involved": len(set(step.get("owner", "") for step in playbook.get("steps", []))),
            "executive_approval_required": playbook.get("severity") == "CRITICAL"
        }
    }
