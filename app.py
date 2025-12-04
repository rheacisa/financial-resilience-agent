"""
Streamlit Web UI for Financial Cyber Resilience Agent

Interactive web interface for assessing financial institution resilience
against cyber threats and operational risks.
"""

import streamlit as st
from typing import Dict, Any
import time

# Import our modules
from financial_system import (
    get_financial_metrics,
    simulate_cyber_attack,
    apply_recovery_action,
    reset_system
)
from threat_intel import get_current_threat_level
from main import create_resilience_agent, extract_json_from_response

# Page configuration
st.set_page_config(
    page_title="🛡️ Financial Cyber Resilience Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .stAlert {
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
</style>
""", unsafe_allow_html=True)


def get_status_indicator(metric_name: str, value: float, threshold: float, higher_is_better: bool = True) -> str:
    """Get status indicator emoji based on metric value vs threshold"""
    if higher_is_better:
        if value >= threshold:
            return "✅ Compliant"
        elif value >= threshold * 0.9:
            return "⚠️ Caution"
        else:
            return "🚨 Critical"
    else:
        # For metrics where lower is better
        if value <= threshold:
            return "✅ Good"
        elif value <= threshold * 1.1:
            return "⚠️ Caution"
        else:
            return "🚨 Critical"


def get_threat_emoji(threat_level: str) -> str:
    """Get emoji for threat level"""
    threat_emojis = {
        "LOW": "🟢",
        "MODERATE": "🟡",
        "ELEVATED": "🟠",
        "HIGH": "🔴",
        "CRITICAL": "⚫"
    }
    return threat_emojis.get(threat_level, "⚪")


def display_system_status():
    """Display current system status in sidebar"""
    st.sidebar.title("🛡️ System Status")
    
    # Get current metrics
    metrics = get_financial_metrics()
    threat_data = get_current_threat_level()
    
    st.sidebar.subheader("📊 Financial Metrics")
    
    current = metrics["current_metrics"]
    
    # Capital Adequacy Ratio
    car_value = float(current["capital_adequacy_ratio"].rstrip('%'))
    car_status = get_status_indicator("CAR", car_value, 10.5)
    st.sidebar.metric(
        "Capital Adequacy Ratio",
        current["capital_adequacy_ratio"],
        delta=None,
        help="Minimum: 10.5%"
    )
    st.sidebar.caption(car_status)
    
    # Liquidity Coverage Ratio
    lcr_value = float(current["liquidity_coverage_ratio"].rstrip('%'))
    lcr_status = get_status_indicator("LCR", lcr_value, 100.0)
    st.sidebar.metric(
        "Liquidity Coverage Ratio",
        current["liquidity_coverage_ratio"],
        delta=None,
        help="Minimum: 100%"
    )
    st.sidebar.caption(lcr_status)
    
    # Cyber Resilience Score
    cyber_value = float(current["cyber_resilience_score"].split('/')[0])
    cyber_status = get_status_indicator("Cyber", cyber_value, 80.0)
    st.sidebar.metric(
        "Cyber Resilience Score",
        current["cyber_resilience_score"],
        delta=None,
        help="Target: 80+"
    )
    st.sidebar.caption(cyber_status)
    
    # Customer Trust Index
    trust_value = float(current["customer_trust_index"].split('/')[0])
    trust_status = get_status_indicator("Trust", trust_value, 90.0)
    st.sidebar.metric(
        "Customer Trust Index",
        current["customer_trust_index"],
        delta=None,
        help="Target: 90+"
    )
    st.sidebar.caption(trust_status)
    
    # System Uptime
    uptime_value = float(current["system_uptime"].rstrip('%'))
    st.sidebar.metric(
        "System Uptime",
        current["system_uptime"],
        delta=None
    )
    
    # Active Incidents
    incidents = current["active_incidents"]
    incident_status = "🚨 Active" if incidents > 0 else "✅ None"
    st.sidebar.metric(
        "Active Incidents",
        incidents,
        delta=None
    )
    st.sidebar.caption(incident_status)
    
    # Threat Level
    st.sidebar.subheader("🎯 Threat Status")
    threat_level = threat_data["financial_sector_threat_level"]
    threat_emoji = get_threat_emoji(threat_level)
    st.sidebar.metric(
        "Financial Sector Threat",
        f"{threat_emoji} {threat_level}",
        delta=None
    )
    st.sidebar.caption(f"{threat_data['threat_count']} active threats")
    
    # Reset button
    st.sidebar.divider()
    if st.sidebar.button("🔄 Reset System to Baseline", use_container_width=True):
        reset_system()
        st.sidebar.success("✅ System reset to baseline state")
        st.rerun()


def initialize_session_state():
    """Initialize session state variables"""
    if "messages" not in st.session_state:
        st.session_state.messages = []
    if "agent" not in st.session_state:
        with st.spinner("🔧 Initializing AI agent..."):
            try:
                st.session_state.agent = create_resilience_agent(verbose=False)
                st.session_state.agent_ready = True
            except Exception as e:
                st.session_state.agent_ready = False
                st.session_state.agent_error = str(e)


def format_agent_response(response: str) -> Dict[str, Any]:
    """Format agent response for display"""
    assessment = extract_json_from_response(response)
    
    # Add response text if not in assessment
    if not assessment.get("reasoning"):
        assessment["reasoning"] = response
    
    return assessment


def main():
    """Main Streamlit application"""
    
    # Initialize session state
    initialize_session_state()
    
    # Display sidebar with system status
    display_system_status()
    
    # Main title
    st.title("🛡️ Financial Cyber Resilience Agent")
    st.caption("Edge-deployed AI agent for financial institution resilience assessment • Powered by Ollama + LangChain")
    
    # Check if agent is ready
    if not st.session_state.agent_ready:
        st.error(f"""
        ❌ **Agent initialization failed**
        
        Error: {st.session_state.get('agent_error', 'Unknown error')}
        
        **Please ensure:**
        1. Ollama is running: `ollama serve`
        2. Mistral model is installed: `ollama pull mistral`
        3. Ollama is accessible at http://localhost:11434
        """)
        return
    
    # Create two columns for main content
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.subheader("💬 Chat with Agent")
        
        # Display chat messages
        for message in st.session_state.messages:
            with st.chat_message(message["role"]):
                if message["role"] == "assistant" and "assessment" in message:
                    # Display structured assessment
                    assessment = message["assessment"]
                    
                    # Risk level with emoji
                    risk_emoji = {"STABLE": "✅", "AT_RISK": "⚠️", "CRITICAL": "🚨"}
                    risk_level = assessment.get("risk_level", "UNKNOWN")
                    st.markdown(f"### {risk_emoji.get(risk_level, '❓')} Risk Level: {risk_level}")
                    
                    # Main response
                    st.markdown(message["content"])
                    
                    # Recommended actions
                    if assessment.get("recommended_actions"):
                        st.markdown("**📋 Recommended Actions:**")
                        for action in assessment["recommended_actions"]:
                            st.markdown(f"- {action}")
                    
                    # Regulatory concerns
                    if assessment.get("regulatory_concerns"):
                        st.warning("**⚖️ Regulatory Concerns:**")
                        for concern in assessment["regulatory_concerns"]:
                            st.markdown(f"- {concern}")
                else:
                    st.markdown(message["content"])
        
        # Example queries
        with st.expander("💡 Example Queries"):
            examples = [
                "What is the current resilience status of our financial institution?",
                "Assess our preparedness for a ransomware attack",
                "What would happen if we experienced a data breach?",
                "Are we in compliance with regulatory requirements?",
                "Simulate a DDoS attack and recommend recovery actions"
            ]
            for example in examples:
                if st.button(example, key=f"example_{example[:20]}"):
                    # Add to messages and process
                    st.session_state.messages.append({"role": "user", "content": example})
                    st.rerun()
        
        # Chat input
        if prompt := st.chat_input("Ask about financial resilience, threats, or incident response..."):
            # Add user message
            st.session_state.messages.append({"role": "user", "content": prompt})
            
            # Display user message
            with st.chat_message("user"):
                st.markdown(prompt)
            
            # Generate response
            with st.chat_message("assistant"):
                with st.spinner("🤖 Analyzing..."):
                    try:
                        result = st.session_state.agent.invoke({"input": prompt})
                        output = result.get("output", "")
                        
                        # Format and display
                        assessment = format_agent_response(output)
                        
                        # Risk level
                        risk_emoji = {"STABLE": "✅", "AT_RISK": "⚠️", "CRITICAL": "🚨"}
                        risk_level = assessment.get("risk_level", "UNKNOWN")
                        st.markdown(f"### {risk_emoji.get(risk_level, '❓')} Risk Level: {risk_level}")
                        
                        # Main response
                        st.markdown(output)
                        
                        # Recommended actions
                        if assessment.get("recommended_actions"):
                            st.markdown("**📋 Recommended Actions:**")
                            for action in assessment["recommended_actions"]:
                                st.markdown(f"- {action}")
                        
                        # Regulatory concerns
                        if assessment.get("regulatory_concerns"):
                            st.warning("**⚖️ Regulatory Concerns:**")
                            for concern in assessment["regulatory_concerns"]:
                                st.markdown(f"- {concern}")
                        
                        # Add to messages
                        st.session_state.messages.append({
                            "role": "assistant",
                            "content": output,
                            "assessment": assessment
                        })
                        
                    except Exception as e:
                        error_msg = f"❌ Error: {str(e)}"
                        st.error(error_msg)
                        st.session_state.messages.append({
                            "role": "assistant",
                            "content": error_msg
                        })
    
    with col2:
        st.subheader("⚡ Quick Actions")
        
        st.markdown("**🎯 Simulate Attacks**")
        st.caption("Model impact of cyber incidents")
        
        if st.button("🔐 Ransomware Attack", use_container_width=True):
            with st.spinner("Simulating ransomware attack..."):
                result = simulate_cyber_attack("ransomware")
                st.error(f"**Attack Simulated:** {result['description']}")
                st.metric("Financial Loss", f"${result['financial_loss_mm']:.2f}MM")
                st.rerun()
        
        if st.button("🌐 DDoS Attack", use_container_width=True):
            with st.spinner("Simulating DDoS attack..."):
                result = simulate_cyber_attack("ddos")
                st.warning(f"**Attack Simulated:** {result['description']}")
                st.metric("Financial Loss", f"${result['financial_loss_mm']:.2f}MM")
                st.rerun()
        
        if st.button("📊 Data Breach", use_container_width=True):
            with st.spinner("Simulating data breach..."):
                result = simulate_cyber_attack("data_breach")
                st.error(f"**Attack Simulated:** {result['description']}")
                st.metric("Financial Loss", f"${result['financial_loss_mm']:.2f}MM")
                st.rerun()
        
        st.divider()
        
        st.markdown("**🔧 Recovery Actions**")
        st.caption("Apply recovery measures")
        
        if st.button("💾 Activate Disaster Recovery", use_container_width=True):
            with st.spinner("Activating DR procedures..."):
                result = apply_recovery_action("disaster_recovery")
                if result["success"]:
                    st.success(f"**Recovery Applied:** {result['description']}")
                    st.metric("Cost", f"${result['cost_mm']:.2f}MM")
                    st.rerun()
        
        if st.button("💰 Liquidity Injection", use_container_width=True):
            with st.spinner("Applying liquidity measures..."):
                result = apply_recovery_action("liquidity_injection")
                if result["success"]:
                    st.success(f"**Recovery Applied:** {result['description']}")
                    st.metric("Cost", f"${result['cost_mm']:.2f}MM")
                    st.rerun()
        
        if st.button("🔒 Deploy Security Patches", use_container_width=True):
            with st.spinner("Deploying security patches..."):
                result = apply_recovery_action("security_patch")
                if result["success"]:
                    st.success(f"**Recovery Applied:** {result['description']}")
                    st.metric("Cost", f"${result['cost_mm']:.2f}MM")
                    st.rerun()
    
    # Footer
    st.divider()
    st.caption("🛡️ Edge-deployed AI agent • No cloud required • Powered by Ollama (Mistral) + LangChain")


if __name__ == "__main__":
    main()
