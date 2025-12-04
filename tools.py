"""
LangChain Tool Wrappers

Provides tool interfaces for the AI agent to interact with financial systems,
threat intelligence, and incident response playbooks.
"""

from langchain_core.tools import tool
from typing import Dict, Any

# Import our data modules
from financial_system import (
    get_financial_metrics,
    get_regulatory_thresholds,
    simulate_cyber_attack,
    apply_recovery_action
)
from threat_intel import (
    get_current_threat_level,
    get_vulnerability_status,
    get_industry_alerts
)
from playbooks import (
    get_playbook,
    get_all_playbooks,
    calculate_recovery_impact
)


@tool
def get_financial_metrics_tool() -> Dict[str, Any]:
    """
    Get current financial institution metrics and regulatory compliance status.
    
    This tool retrieves real-time financial health indicators including:
    - Capital Adequacy Ratio (minimum 10.5% required)
    - Liquidity Coverage Ratio (minimum 100% required)
    - Cyber Resilience Score (target 80+)
    - Customer Trust Index (target 90+)
    - System Uptime percentage
    - Active security incidents count
    
    Use this tool when you need to:
    - Assess current financial health and regulatory compliance
    - Determine if institution meets minimum regulatory requirements
    - Get baseline metrics before simulating attacks or recovery actions
    - Monitor the impact of incidents on financial stability
    
    Returns:
        Dictionary containing current metrics, regulatory status, and compliance indicators
    """
    return get_financial_metrics()


@tool
def get_threat_intelligence_tool() -> Dict[str, Any]:
    """
    Get current cybersecurity threat intelligence and vulnerability status.
    
    This tool provides comprehensive threat landscape information including:
    - Overall and financial sector-specific threat levels
    - Active threats targeting financial institutions
    - Vulnerability counts (critical, high, medium, low)
    - Patch compliance percentage
    - Security exposure score and rating
    - Industry alerts from FS-ISAC and CISA
    
    Use this tool when you need to:
    - Assess the current threat environment
    - Understand which threats are actively targeting financial institutions
    - Evaluate vulnerability exposure and patch status
    - Review recent security alerts and advisories
    - Determine appropriate security posture
    
    Returns:
        Dictionary containing threat levels, active threats, vulnerabilities, and industry alerts
    """
    threat_data = get_current_threat_level()
    vuln_data = get_vulnerability_status()
    alert_data = get_industry_alerts()
    
    return {
        "threat_intelligence": threat_data,
        "vulnerability_status": vuln_data,
        "industry_alerts": alert_data
    }


@tool
def get_incident_playbook_tool(incident_type: str) -> Dict[str, Any]:
    """
    Get detailed incident response playbook for a specific incident type.
    
    Available incident types:
    - ransomware: Response to ransomware attacks with encryption and extortion
    - ddos: Response to distributed denial of service attacks
    - data_breach: Response to unauthorized access and data exfiltration
    - liquidity_crisis: Response to liquidity stress and funding issues
    - disaster_recovery: Business continuity and disaster recovery activation
    
    Each playbook includes:
    - Step-by-step response procedures
    - Regulatory notification requirements and timeframes
    - Recovery time objectives (RTO) and recovery point objectives (RPO)
    - Required notifications to regulators (OCC, FDIC, SEC, etc.)
    - Critical "do not" items to avoid
    
    Use this tool when you need to:
    - Get specific response procedures for an incident
    - Understand regulatory notification requirements
    - Review step-by-step incident response actions
    - Determine recovery objectives and timelines
    
    Args:
        incident_type: Type of incident (ransomware, data_breach, liquidity_crisis, disaster_recovery, ddos)
    
    Returns:
        Dictionary containing complete incident response playbook with steps, notifications, and metrics
    """
    playbook = get_playbook(incident_type)
    
    if not playbook:
        return {
            "error": f"Playbook not found for incident type: {incident_type}",
            "available_types": ["ransomware", "data_breach", "liquidity_crisis", "disaster_recovery"],
            "suggestion": "Use one of the available incident types"
        }
    
    return playbook


@tool
def simulate_attack_impact_tool(attack_type: str) -> Dict[str, Any]:
    """
    Simulate a cyber attack and calculate its impact on financial metrics.
    
    ⚠️ WARNING: This tool MODIFIES the financial system state by simulating real impacts.
    Use only when specifically requested or when analyzing "what-if" scenarios.
    
    Available attack types:
    - ransomware: Encrypts systems, impacts cyber resilience, uptime, and trust ($5-20MM loss)
    - ddos: Overwhelms network, impacts uptime and cyber resilience ($1-5MM loss)
    - data_breach: Exposes customer data, major trust and capital impact ($10-50MM loss)
    
    Impact includes:
    - Financial losses in millions of USD
    - Degradation of cyber resilience score
    - Reduction in system uptime
    - Decline in customer trust index
    - Potential impact on capital adequacy
    - Increment in active incidents count
    
    Use this tool when you need to:
    - Model the potential impact of a specific attack type
    - Demonstrate vulnerability to certain threats
    - Test incident response preparedness
    - Support risk assessment scenarios
    
    Args:
        attack_type: Type of attack to simulate (ransomware, ddos, data_breach)
    
    Returns:
        Dictionary containing attack details, impacts, financial losses, and updated metrics
    """
    return simulate_cyber_attack(attack_type)


@tool
def calculate_recovery_outlook_tool(playbook_name: str) -> Dict[str, Any]:
    """
    Calculate projected recovery impact and resource requirements for a playbook.
    
    This tool analyzes an incident response playbook and projects:
    - Total estimated duration in hours
    - Expected improvements to impacted metrics
    - Estimated costs in millions of USD
    - Number of regulatory notifications required
    - Success probability percentage
    - Resource requirements (teams, approvals)
    
    Available playbooks:
    - ransomware: Recovery from ransomware attacks
    - liquidity_crisis: Resolution of liquidity stress
    - disaster_recovery: DR activation and failover
    - data_breach: Breach response and remediation
    
    Use this tool when you need to:
    - Estimate recovery timeline and costs
    - Project metric improvements from playbook execution
    - Understand resource requirements for response
    - Evaluate feasibility of recovery actions
    - Support decision-making on response strategies
    
    Args:
        playbook_name: Name of playbook to analyze (ransomware, liquidity_crisis, disaster_recovery, data_breach)
    
    Returns:
        Dictionary containing recovery projections, costs, duration, and resource requirements
    """
    return calculate_recovery_impact(playbook_name)


@tool
def apply_recovery_action_tool(action_type: str) -> Dict[str, Any]:
    """
    Apply a recovery action to improve system metrics after an incident.
    
    Available recovery actions:
    - disaster_recovery: Activates DR procedures, restores from backups
      * Improves: system uptime (+3-8%), cyber resilience (+5-15 points)
      * Cost: $0.5-2MM
      * Resolves active incidents
    
    - liquidity_injection: Emergency liquidity support measures
      * Improves: liquidity coverage (+10-25%), capital adequacy (+0.5-2%)
      * Cost: $0.2-1MM
      * Stabilizes financial position
    
    - security_patch: Deploy security patches and hardening
      * Improves: cyber resilience (+10-20 points), customer trust (+3-8 points)
      * Cost: $0.1-0.5MM
      * Reduces vulnerability exposure
    
    Use this tool when you need to:
    - Execute recovery actions after incident simulation
    - Improve degraded metrics
    - Test recovery effectiveness
    - Restore regulatory compliance
    - Demonstrate recovery capabilities
    
    Args:
        action_type: Type of recovery action (disaster_recovery, liquidity_injection, security_patch)
    
    Returns:
        Dictionary containing action results, improvements made, costs, and updated metrics
    """
    return apply_recovery_action(action_type)


# Export all tools as a list for easy agent configuration
ALL_TOOLS = [
    get_financial_metrics_tool,
    get_threat_intelligence_tool,
    get_incident_playbook_tool,
    simulate_attack_impact_tool,
    calculate_recovery_outlook_tool,
    apply_recovery_action_tool
]
