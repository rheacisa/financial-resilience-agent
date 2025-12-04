"""
Simulated Financial System State and Operations

Provides realistic simulation of financial institution metrics,
regulatory thresholds, and impact modeling for cyber incidents.
"""

from dataclasses import dataclass, field
from typing import Dict, Any
import random


@dataclass
class FinancialSystemState:
    """Current state of the financial institution"""
    capital_adequacy_ratio: float = 12.5  # Minimum regulatory: 10.5%
    liquidity_coverage_ratio: float = 135.0  # Minimum regulatory: 100%
    cyber_resilience_score: float = 95.0  # Target: 80+
    customer_trust_index: float = 98.0  # Target: 90+
    system_uptime: float = 99.9  # Percentage
    active_incidents: int = 0


# Global system state
_system_state = FinancialSystemState()


def get_financial_metrics() -> Dict[str, Any]:
    """
    Get current financial system metrics and status
    
    Returns:
        Dictionary with current metrics and regulatory compliance status
    """
    return {
        "current_metrics": {
            "capital_adequacy_ratio": f"{_system_state.capital_adequacy_ratio:.2f}%",
            "liquidity_coverage_ratio": f"{_system_state.liquidity_coverage_ratio:.2f}%",
            "cyber_resilience_score": f"{_system_state.cyber_resilience_score:.1f}/100",
            "customer_trust_index": f"{_system_state.customer_trust_index:.1f}/100",
            "system_uptime": f"{_system_state.system_uptime:.2f}%",
            "active_incidents": _system_state.active_incidents
        },
        "regulatory_status": {
            "capital_adequacy": "COMPLIANT" if _system_state.capital_adequacy_ratio >= 10.5 else "NON_COMPLIANT",
            "liquidity_coverage": "COMPLIANT" if _system_state.liquidity_coverage_ratio >= 100.0 else "NON_COMPLIANT",
            "cyber_resilience": "ADEQUATE" if _system_state.cyber_resilience_score >= 80.0 else "INADEQUATE",
            "customer_trust": "ADEQUATE" if _system_state.customer_trust_index >= 90.0 else "INADEQUATE"
        },
        "timestamp": "real-time"
    }


def get_regulatory_thresholds() -> Dict[str, Any]:
    """
    Get regulatory thresholds and targets for financial institutions
    
    Returns:
        Dictionary with minimum requirements and targets
    """
    return {
        "capital_adequacy_ratio": {
            "minimum": "10.5%",
            "current": f"{_system_state.capital_adequacy_ratio:.2f}%",
            "status": "COMPLIANT" if _system_state.capital_adequacy_ratio >= 10.5 else "NON_COMPLIANT"
        },
        "liquidity_coverage_ratio": {
            "minimum": "100%",
            "current": f"{_system_state.liquidity_coverage_ratio:.2f}%",
            "status": "COMPLIANT" if _system_state.liquidity_coverage_ratio >= 100.0 else "NON_COMPLIANT"
        },
        "cyber_resilience_score": {
            "target": "80+",
            "current": f"{_system_state.cyber_resilience_score:.1f}/100",
            "status": "ADEQUATE" if _system_state.cyber_resilience_score >= 80.0 else "INADEQUATE"
        },
        "customer_trust_index": {
            "target": "90+",
            "current": f"{_system_state.customer_trust_index:.1f}/100",
            "status": "ADEQUATE" if _system_state.customer_trust_index >= 90.0 else "INADEQUATE"
        }
    }


def simulate_cyber_attack(attack_type: str) -> Dict[str, Any]:
    """
    Simulate a cyber attack and apply realistic impacts to system metrics
    
    Args:
        attack_type: Type of attack (ransomware, ddos, data_breach)
    
    Returns:
        Dictionary with impact details and updated metrics
    """
    attack_type = attack_type.lower()
    
    impacts = {
        "attack_type": attack_type,
        "severity": "",
        "financial_loss_mm": 0.0,
        "metrics_impacted": {},
        "incident_id": f"INC-{random.randint(1000, 9999)}"
    }
    
    if attack_type == "ransomware":
        # Ransomware: Major operational and trust impact
        cyber_impact = random.uniform(-50, -30)
        uptime_impact = random.uniform(-15, -5)
        trust_impact = random.uniform(-20, -10)
        financial_loss = random.uniform(5, 20)
        
        _system_state.cyber_resilience_score = max(0, _system_state.cyber_resilience_score + cyber_impact)
        _system_state.system_uptime = max(0, _system_state.system_uptime + uptime_impact)
        _system_state.customer_trust_index = max(0, _system_state.customer_trust_index + trust_impact)
        _system_state.active_incidents += 1
        
        impacts.update({
            "severity": "CRITICAL",
            "financial_loss_mm": round(financial_loss, 2),
            "metrics_impacted": {
                "cyber_resilience_score": f"{cyber_impact:.1f} points",
                "system_uptime": f"{uptime_impact:.1f}%",
                "customer_trust_index": f"{trust_impact:.1f} points"
            },
            "description": "Ransomware attack encrypted critical systems, causing operational disruption"
        })
    
    elif attack_type == "ddos":
        # DDoS: Availability impact
        cyber_impact = random.uniform(-20, -10)
        uptime_impact = random.uniform(-8, -2)
        financial_loss = random.uniform(1, 5)
        
        _system_state.cyber_resilience_score = max(0, _system_state.cyber_resilience_score + cyber_impact)
        _system_state.system_uptime = max(0, _system_state.system_uptime + uptime_impact)
        _system_state.active_incidents += 1
        
        impacts.update({
            "severity": "HIGH",
            "financial_loss_mm": round(financial_loss, 2),
            "metrics_impacted": {
                "cyber_resilience_score": f"{cyber_impact:.1f} points",
                "system_uptime": f"{uptime_impact:.1f}%"
            },
            "description": "Distributed Denial of Service attack overwhelmed network infrastructure"
        })
    
    elif attack_type == "data_breach":
        # Data Breach: Major trust and capital impact
        trust_impact = random.uniform(-40, -25)
        capital_impact = random.uniform(-3, -1)
        financial_loss = random.uniform(10, 50)
        
        _system_state.customer_trust_index = max(0, _system_state.customer_trust_index + trust_impact)
        _system_state.capital_adequacy_ratio = max(0, _system_state.capital_adequacy_ratio + capital_impact)
        _system_state.active_incidents += 1
        
        impacts.update({
            "severity": "CRITICAL",
            "financial_loss_mm": round(financial_loss, 2),
            "metrics_impacted": {
                "customer_trust_index": f"{trust_impact:.1f} points",
                "capital_adequacy_ratio": f"{capital_impact:.2f}%"
            },
            "description": "Data breach exposed sensitive customer information, requiring regulatory notification"
        })
    
    else:
        impacts.update({
            "severity": "UNKNOWN",
            "description": f"Unknown attack type: {attack_type}",
            "error": "Valid attack types: ransomware, ddos, data_breach"
        })
    
    impacts["updated_metrics"] = get_financial_metrics()
    return impacts


def apply_recovery_action(action_type: str) -> Dict[str, Any]:
    """
    Apply recovery action to improve system metrics
    
    Args:
        action_type: Type of recovery (disaster_recovery, liquidity_injection, security_patch)
    
    Returns:
        Dictionary with recovery results and updated metrics
    """
    action_type = action_type.lower()
    
    recovery = {
        "action_type": action_type,
        "success": False,
        "improvements": {},
        "cost_mm": 0.0
    }
    
    if action_type == "disaster_recovery":
        # Activate disaster recovery procedures
        uptime_improvement = random.uniform(3, 8)
        cyber_improvement = random.uniform(5, 15)
        cost = random.uniform(0.5, 2)
        
        _system_state.system_uptime = min(100, _system_state.system_uptime + uptime_improvement)
        _system_state.cyber_resilience_score = min(100, _system_state.cyber_resilience_score + cyber_improvement)
        if _system_state.active_incidents > 0:
            _system_state.active_incidents -= 1
        
        recovery.update({
            "success": True,
            "cost_mm": round(cost, 2),
            "improvements": {
                "system_uptime": f"+{uptime_improvement:.1f}%",
                "cyber_resilience_score": f"+{cyber_improvement:.1f} points",
                "active_incidents": "resolved 1 incident" if _system_state.active_incidents >= 0 else "no incidents"
            },
            "description": "Disaster recovery procedures activated, systems restored from backups"
        })
    
    elif action_type == "liquidity_injection":
        # Emergency liquidity support
        liquidity_improvement = random.uniform(10, 25)
        capital_improvement = random.uniform(0.5, 2)
        cost = random.uniform(0.2, 1)
        
        _system_state.liquidity_coverage_ratio = min(200, _system_state.liquidity_coverage_ratio + liquidity_improvement)
        _system_state.capital_adequacy_ratio = min(20, _system_state.capital_adequacy_ratio + capital_improvement)
        
        recovery.update({
            "success": True,
            "cost_mm": round(cost, 2),
            "improvements": {
                "liquidity_coverage_ratio": f"+{liquidity_improvement:.1f}%",
                "capital_adequacy_ratio": f"+{capital_improvement:.2f}%"
            },
            "description": "Emergency liquidity measures activated, capital position strengthened"
        })
    
    elif action_type == "security_patch":
        # Apply security patches and hardening
        cyber_improvement = random.uniform(10, 20)
        trust_improvement = random.uniform(3, 8)
        cost = random.uniform(0.1, 0.5)
        
        _system_state.cyber_resilience_score = min(100, _system_state.cyber_resilience_score + cyber_improvement)
        _system_state.customer_trust_index = min(100, _system_state.customer_trust_index + trust_improvement)
        
        recovery.update({
            "success": True,
            "cost_mm": round(cost, 2),
            "improvements": {
                "cyber_resilience_score": f"+{cyber_improvement:.1f} points",
                "customer_trust_index": f"+{trust_improvement:.1f} points"
            },
            "description": "Security patches deployed, vulnerabilities remediated"
        })
    
    else:
        recovery.update({
            "success": False,
            "description": f"Unknown action type: {action_type}",
            "error": "Valid actions: disaster_recovery, liquidity_injection, security_patch"
        })
    
    if recovery["success"]:
        recovery["updated_metrics"] = get_financial_metrics()
    
    return recovery


def reset_system() -> Dict[str, Any]:
    """
    Reset system to baseline state
    
    Returns:
        Dictionary with reset confirmation and baseline metrics
    """
    global _system_state
    _system_state = FinancialSystemState()
    
    return {
        "status": "RESET_COMPLETE",
        "message": "System restored to baseline state",
        "baseline_metrics": get_financial_metrics()
    }
