"""
Financial Cyber Resilience Agent - Streamlit Web UI

This provides a web-based interface for the Financial Cyber Resilience AI Agent
with integrated security features and monitoring.

Features:
- Interactive chat interface with LLM agent
- Real-time security monitoring
- Audit log viewer
- Security metrics dashboard
- RBAC role selection

Usage:
    streamlit run app.py
"""

import streamlit as st
from datetime import datetime
from typing import List, Dict
from security.guardrails import GuardrailPipeline
from security.rbac import Role, User


# Page configuration
st.set_page_config(
    page_title="Financial Cyber Resilience Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


class StreamlitFinancialAgent:
    """
    Financial Cyber Resilience Agent adapted for Streamlit UI
    """
    
    def __init__(self, strict_mode: bool = True):
        """Initialize agent with security guardrails"""
        if 'guardrails' not in st.session_state:
            st.session_state.guardrails = GuardrailPipeline(strict_mode=strict_mode)
        self.guardrails = st.session_state.guardrails
    
    def simulate_response(self, query: str) -> str:
        """Simulate agent response (stub for demonstration)"""
        query_lower = query.lower()
        
        if "resilience" in query_lower or "posture" in query_lower:
            return """**Cyber Resilience Posture: MODERATE**

📊 **Key Metrics:**
- Capital Adequacy Ratio (CAR): 12.5% ✅ (above minimum 10.5%)
- Liquidity Coverage Ratio (LCR): 115% ✅ (above minimum 100%)
- Incident Response: Active monitoring in place
- Recovery Capabilities: Tested quarterly
- Compliance Framework: NIST CSF, ISO 27001

🎯 **Recommendations:**
1. Enhance threat intelligence integration
2. Conduct additional stress testing
3. Review third-party risk management
"""
        elif "attack" in query_lower or "threat" in query_lower:
            return """**Threat Landscape Analysis**

🚨 **HIGH PRIORITY THREATS:**
- Ransomware attacks targeting financial institutions (+45% YoY)
- Supply chain compromises
- Insider threats
- API vulnerabilities

🛡️ **RECOMMENDED MITIGATIONS:**
- Implement zero-trust architecture
- Deploy enhanced endpoint detection and response (EDR)
- Conduct regular security awareness training
- Enforce multi-factor authentication (MFA)
"""
        elif "compliance" in query_lower or "regulation" in query_lower:
            return """**Regulatory Compliance Requirements**

📋 **ACTIVE REGULATIONS:**
- Federal Reserve - Capital Requirements
- FFIEC - Cybersecurity Assessment Tool
- OCC - Heightened Standards
- SEC - Cybersecurity Disclosure Rules
- GLBA - Financial Privacy Rule

✅ **COMPLIANCE STATUS:**
Your institution should maintain:
- Risk assessments (annual)
- Incident response plans (tested quarterly)
- Third-party risk management
- Security awareness training records
"""
        else:
            return f"""I understand you're asking about: **{query}**

For financial cyber resilience assessments, I can help with:
- 📊 Current security posture analysis
- 🎯 Threat landscape evaluation
- 📋 Regulatory compliance guidance
- 🚨 Incident response planning
- 🔄 Recovery capability assessment

Please provide more specific details about your inquiry.
"""
    
    def process_query(self, user_input: str, user_role: str = "analyst") -> Dict:
        """Process query with full security pipeline"""
        result = {
            "status": "success",
            "response": "",
            "warnings": [],
            "blocked": False
        }
        
        # Validate input
        is_safe, sanitized, input_results = self.guardrails.validate_input(
            user_input, user_role=user_role
        )
        
        if not is_safe:
            blocked_reasons = [
                r.message for r in input_results if not r.passed or r.blocked
            ]
            result["status"] = "blocked"
            result["blocked"] = True
            result["response"] = "🚫 **Query Blocked by Security Guardrails**\n\n" + "\n".join(
                f"- {reason}" for reason in blocked_reasons
            )
            return result
        
        # Check if input was sanitized
        if sanitized != user_input:
            result["warnings"].append("🔒 Input sanitized: PII detected and masked")
        
        # Process with agent
        agent_output = self.simulate_response(sanitized)
        
        # Validate output
        output_safe, sanitized_output, output_results = self.guardrails.validate_output(
            agent_output, user_role=user_role
        )
        
        if not output_safe:
            blocked_reasons = [
                r.message for r in output_results if not r.passed or r.blocked
            ]
            result["status"] = "blocked"
            result["blocked"] = True
            result["response"] = "🚫 **Response Blocked by Security Guardrails**\n\n" + "\n".join(
                f"- {reason}" for reason in blocked_reasons
            )
            return result
        
        # Check for hallucination warnings
        hallucination_warnings = [
            r.message for r in output_results 
            if r.threat_type and r.threat_type.value == "hallucination"
        ]
        
        if hallucination_warnings:
            result["warnings"].extend([f"⚠️ {w}" for w in hallucination_warnings])
        
        result["response"] = sanitized_output
        return result


def render_sidebar():
    """Render sidebar with security controls and monitoring"""
    st.sidebar.title("🛡️ Security Dashboard")
    
    # Role selection
    st.sidebar.subheader("👤 User Role")
    role_options = ["Viewer", "Analyst", "Examiner", "Admin"]
    selected_role = st.sidebar.selectbox(
        "Select Role",
        role_options,
        index=1,
        help="Role-Based Access Control (RBAC) demonstration"
    )
    st.session_state.user_role = selected_role.lower()
    
    # Security mode
    st.sidebar.subheader("🔐 Security Settings")
    strict_mode = st.sidebar.checkbox(
        "Strict Mode",
        value=True,
        help="Enable strict security validation"
    )
    
    if strict_mode:
        st.sidebar.metric("Security Mode", "🛡️ STRICT", delta="Protected")
    else:
        st.sidebar.metric("Security Mode", "⚠️ PERMISSIVE", delta="Reduced Protection")
    
    # Security metrics
    st.sidebar.subheader("📊 Security Metrics")
    if 'guardrails' in st.session_state:
        audit_log = st.session_state.guardrails.get_audit_log()
        total_events = len(audit_log)
        blocked_events = sum(1 for e in audit_log if e['result'] == 'BLOCKED')
        sanitized_events = sum(1 for e in audit_log if e['result'] == 'SANITIZED')
        
        col1, col2 = st.sidebar.columns(2)
        col1.metric("Total Queries", total_events)
        col2.metric("Blocked", blocked_events)
        
        col3, col4 = st.sidebar.columns(2)
        col3.metric("Sanitized", sanitized_events)
        col4.metric("Success Rate", f"{((total_events - blocked_events) / max(total_events, 1) * 100):.0f}%")
    
    # Audit log viewer
    st.sidebar.subheader("📋 Audit Log")
    with st.sidebar.expander("View Recent Events", expanded=False):
        if 'guardrails' in st.session_state:
            audit_log = st.session_state.guardrails.get_audit_log()
            for entry in audit_log[-10:]:
                icon = "🚫" if entry['result'] == 'BLOCKED' else "✅" if entry['result'] == 'PASSED' else "⚠️"
                timestamp = entry['timestamp'][11:19]
                event = entry['event_type'][:15]
                st.sidebar.text(f"{icon} [{timestamp}] {event}")
        else:
            st.sidebar.info("No events yet")
    
    # OWASP LLM Top 10 reference
    st.sidebar.subheader("🔗 Security Standards")
    with st.sidebar.expander("OWASP LLM Top 10", expanded=False):
        st.sidebar.markdown("""
        **Active Guardrails:**
        - ✅ LLM01: Prompt Injection
        - ✅ LLM02: Insecure Output
        - ✅ LLM03: Training Data Poisoning
        - ✅ LLM04: Model DoS
        - ✅ LLM06: Sensitive Data
        - ✅ LLM09: Overreliance
        
        [Learn More](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
        """)


def render_main_interface(agent: StreamlitFinancialAgent):
    """Render main chat interface"""
    st.title("🏦 Financial Cyber Resilience Agent")
    st.markdown("**Powered by Ollama + LangChain | Secured by Design**")
    
    # Initialize chat history
    if 'chat_history' not in st.session_state:
        st.session_state.chat_history = []
    
    # Example queries
    st.markdown("### 💡 Example Queries")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📊 Check Resilience Posture", use_container_width=True):
            st.session_state.example_query = "What is our current cyber resilience posture?"
    
    with col2:
        if st.button("🎯 Analyze Threats", use_container_width=True):
            st.session_state.example_query = "What are the current threats to financial institutions?"
    
    with col3:
        if st.button("📋 Compliance Info", use_container_width=True):
            st.session_state.example_query = "What are the compliance requirements?"
    
    # Query input
    st.markdown("---")
    query = st.text_area(
        "🔍 Enter your query:",
        value=st.session_state.get('example_query', ''),
        height=100,
        placeholder="e.g., What is our current cyber resilience posture?"
    )
    
    if 'example_query' in st.session_state:
        del st.session_state.example_query
    
    col1, col2, col3 = st.columns([1, 1, 4])
    
    with col1:
        submit = st.button("🚀 Submit Query", type="primary", use_container_width=True)
    
    with col2:
        if st.button("🗑️ Clear History", use_container_width=True):
            st.session_state.chat_history = []
            st.rerun()
    
    # Process query
    if submit and query:
        with st.spinner("🔄 Processing query with security validation..."):
            user_role = st.session_state.get('user_role', 'analyst')
            result = agent.process_query(query, user_role=user_role)
            
            # Add to chat history
            st.session_state.chat_history.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "query": query,
                "result": result,
                "role": user_role
            })
    
    # Display chat history
    st.markdown("---")
    st.markdown("### 💬 Conversation History")
    
    if st.session_state.chat_history:
        for i, chat in enumerate(reversed(st.session_state.chat_history)):
            with st.container():
                st.markdown(f"**[{chat['timestamp']}] Query #{len(st.session_state.chat_history) - i}** (Role: {chat['role']})")
                st.info(f"**Q:** {chat['query']}")
                
                # Show warnings if any
                if chat['result']['warnings']:
                    for warning in chat['result']['warnings']:
                        st.warning(warning)
                
                # Show response
                if chat['result']['blocked']:
                    st.error(chat['result']['response'])
                else:
                    st.success(chat['result']['response'])
                
                st.markdown("---")
    else:
        st.info("No queries yet. Try one of the example queries above or enter your own.")
    
    # Security information
    with st.expander("🔐 Security Features", expanded=False):
        st.markdown("""
        This application demonstrates **secure-by-design principles** for LLM applications in regulated financial environments.
        
        **Active Security Guardrails:**
        
        | Guardrail | Protection | OWASP LLM |
        |-----------|------------|-----------|
        | 🛡️ **Prompt Injection Detection** | Blocks jailbreak attempts and instruction overrides | LLM01 |
        | 🚫 **Output Toxicity Filter** | Prevents violent or harmful responses | LLM02 |
        | ⚠️ **Hallucination Detection** | Flags factually incorrect outputs | LLM09 |
        | 🔒 **PII/Sensitive Data Masking** | Auto-redacts SSN, credit cards, emails | LLM06 |
        | 🔍 **Data Poisoning Detection** | Validates tool outputs for integrity | LLM03 |
        | ⏱️ **Rate Limiting** | Prevents abuse and DoS attacks | LLM04 |
        
        **Compliance Features:**
        - ✅ Immutable audit trail
        - ✅ Privacy by design (input hashing)
        - ✅ Role-Based Access Control
        - ✅ Defense in depth
        """)


def main():
    """Main application entry point"""
    # Initialize agent
    agent = StreamlitFinancialAgent(strict_mode=True)
    
    # Render UI components
    render_sidebar()
    render_main_interface(agent)
    
    # Footer
    st.markdown("---")
    st.markdown(
        """
        <div style='text-align: center; color: gray; font-size: 0.9em;'>
        🛡️ Financial Cyber Resilience Agent | Demonstrating Secure-by-Design Principles<br>
        Built with security-first architecture for regulated financial environments
        </div>
        """,
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()
