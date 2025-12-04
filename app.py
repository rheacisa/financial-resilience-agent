import streamlit as st
import json
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="Financial Resilience Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1E3A5F;
        text-align: center;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #4A6FA5;
        text-align: center;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    .risk-high {
        color: #FF4B4B;
        font-weight: bold;
    }
    .risk-medium {
        color: #FFA500;
        font-weight: bold;
    }
    .risk-low {
        color: #00CC66;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown('<p class="main-header">🛡️ Financial Cyber Resilience Agent</p>', unsafe_allow_html=True)
st.markdown('<p class="sub-header">AI-powered assessment for financial infrastructure security</p>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/security-checked--v1.png", width=80)
    st.title("Configuration")
    
    st.subheader("Assessment Settings")
    assessment_type = st.selectbox(
        "Assessment Type",
        ["Full Security Audit", "Vulnerability Scan", "Compliance Check", "Incident Response Readiness"]
    )
    
    industry_sector = st.selectbox(
        "Industry Sector",
        ["Banking", "Insurance", "Investment", "Fintech", "Credit Union", "Other"]
    )
    
    organization_size = st.selectbox(
        "Organization Size",
        ["Small (1-50 employees)", "Medium (51-500 employees)", "Large (500+ employees)"]
    )
    
    st.divider()
    
    st.subheader("AI Model Settings")
    # model_provider = st.selectbox(
    #     "Model Provider",
    #     ["Ollama (Local)", "OpenAI", "Anthropic"]
    # )
    st.info("🔒 Running with local AI models for data privacy")
    
    st.divider()
    st.caption("Built with Streamlit + LangChain")

# Main content area
tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "🔍 Assessment", "📋 Reports", "⚙️ Settings"])

with tab1:
    st.header("Security Posture Overview")
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="Overall Risk Score",
            value="72/100",
            delta="-5 from last month",
            delta_color="normal"
        )
    
    with col2:
        st.metric(
            label="Vulnerabilities",
            value="23",
            delta="3 new",
            delta_color="inverse"
        )
    
    with col3:
        st.metric(
            label="Compliance Rate",
            value="94%",
            delta="2%",
            delta_color="normal"
        )
    
    with col4:
        st.metric(
            label="Last Assessment",
            value="2 days ago",
            delta=None
        )
    
    st.divider()
    
    # Risk categories
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Risk Categories")
        risk_data = {
            "Network Security": {"score": 85, "status": "Low"},
            "Data Protection": {"score": 72, "status": "Medium"},
            "Access Control": {"score": 68, "status": "Medium"},
            "Incident Response": {"score": 45, "status": "High"},
            "Third-Party Risk": {"score": 78, "status": "Low"},
        }
        
        for category, data in risk_data.items():
            status_class = f"risk-{data['status'].lower()}"
            st.markdown(f"""
            **{category}**  
            Score: {data['score']}/100 | Status: <span class="{status_class}">{data['status']} Risk</span>
            """, unsafe_allow_html=True)
            st.progress(data['score'] / 100)
    
    with col2:
        st.subheader("Recent Alerts")
        alerts = [
            {"time": "2 hours ago", "type": "Warning", "message": "Unusual login pattern detected"},
            {"time": "5 hours ago", "type": "Info", "message": "Security patch available for system"},
            {"time": "1 day ago", "type": "Critical", "message": "Failed authentication attempts exceeded threshold"},
            {"time": "2 days ago", "type": "Info", "message": "Compliance report generated"},
        ]
        
        for alert in alerts:
            icon = "🔴" if alert["type"] == "Critical" else "🟡" if alert["type"] == "Warning" else "🔵"
            st.markdown(f"{icon} **{alert['type']}** - {alert['message']}  \n*{alert['time']}*")

with tab2:
    st.header("Run Security Assessment")
    
    st.markdown("""
    Use the AI-powered assessment tool to analyze your financial infrastructure's cyber resilience.
    The agent will evaluate your security posture and provide actionable recommendations.
    """)
    
    # Assessment input
    assessment_query = st.text_area(
        "Describe your security concern or what you'd like to assess:",
        placeholder="Example: Evaluate our current authentication mechanisms and identify potential vulnerabilities in our customer-facing banking portal...",
        height=150
    )
    
    col1, col2, col3 = st.columns([1, 1, 2])
    
    with col1:
        include_compliance = st.checkbox("Include Compliance Check", value=True)
    
    with col2:
        include_recommendations = st.checkbox("Generate Recommendations", value=True)
    
    if st.button("🚀 Run Assessment", type="primary", use_container_width=True):
        if assessment_query:
            with st.spinner("AI Agent analyzing your security posture..."):
                # Placeholder for actual AI agent integration
                import time
                time.sleep(2)  # Simulate processing
                
                st.success("Assessment Complete!")
                
                # Sample response (replace with actual LangChain agent response)
                st.subheader("Assessment Results")
                
                with st.expander("🔍 Findings", expanded=True):
                    st.markdown("""
                    ### Key Findings
                    
                    Based on the assessment of your authentication mechanisms:
                    
                    1. **Multi-Factor Authentication (MFA)**
                       - Current implementation covers 78% of user accounts
                       - Recommendation: Extend MFA to all administrative accounts
                    
                    2. **Password Policy**
                       - Meets basic requirements but lacks complexity rules
                       - Recommendation: Implement password complexity requirements
                    
                    3. **Session Management**
                       - Session timeout set to 30 minutes (acceptable)
                       - Consider implementing adaptive session management
                    
                    4. **API Authentication**
                       - OAuth 2.0 implementation detected
                       - Token refresh mechanism needs review
                    """)
                
                if include_compliance:
                    with st.expander("📋 Compliance Status"):
                        st.markdown("""
                        | Framework | Status | Coverage |
                        |-----------|--------|----------|
                        | PCI-DSS | ⚠️ Partial | 85% |
                        | SOC 2 | ✅ Compliant | 92% |
                        | GDPR | ✅ Compliant | 88% |
                        | NIST CSF | ⚠️ Partial | 76% |
                        """)
                
                if include_recommendations:
                    with st.expander("💡 Recommendations"):
                        st.markdown("""
                        ### Priority Actions
                        
                        1. **High Priority**: Implement MFA for all accounts within 30 days
                        2. **High Priority**: Update password policy to require 12+ characters
                        3. **Medium Priority**: Review and update API token lifecycle
                        4. **Low Priority**: Consider biometric authentication for mobile app
                        """)
        else:
            st.warning("Please describe what you'd like to assess.")

with tab3:
    st.header("Assessment Reports")
    
    st.markdown("View and download previous assessment reports.")
    
    # Sample reports
    reports = [
        {"date": "2024-12-01", "type": "Full Security Audit", "status": "Completed", "score": 72},
        {"date": "2024-11-15", "type": "Vulnerability Scan", "status": "Completed", "score": 78},
        {"date": "2024-11-01", "type": "Compliance Check", "status": "Completed", "score": 85},
        {"date": "2024-10-15", "type": "Incident Response Readiness", "status": "Completed", "score": 65},
    ]
    
    for report in reports:
        col1, col2, col3, col4, col5 = st.columns([2, 2, 1, 1, 1])
        
        with col1:
            st.write(f"📄 {report['type']}")
        with col2:
            st.write(report['date'])
        with col3:
            st.write(f"Score: {report['score']}")
        with col4:
            st.write(f"✅ {report['status']}")
        with col5:
            st.button("Download", key=f"download_{report['date']}")
        
        st.divider()

with tab4:
    st.header("Settings")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Notification Preferences")
        st.checkbox("Email alerts for critical findings", value=True)
        st.checkbox("Weekly summary reports", value=True)
        st.checkbox("Real-time vulnerability notifications", value=False)
        
        st.subheader("API Configuration")
        st.text_input("API Endpoint", value="https://api.example.com/v1", disabled=True)
        st.text_input("API Key", type="password", placeholder="Enter your API key")
    
    with col2:
        st.subheader("Assessment Defaults")
        st.slider("Risk Threshold", 0, 100, 70)
        st.multiselect(
            "Default Compliance Frameworks",
            ["PCI-DSS", "SOC 2", "GDPR", "NIST CSF", "ISO 27001"],
            default=["PCI-DSS", "SOC 2"]
        )
        
        st.subheader("Data Retention")
        st.selectbox("Keep reports for", ["30 days", "90 days", "1 year", "Forever"])
    
    st.divider()
    
    if st.button("💾 Save Settings", type="primary"):
        st.success("Settings saved successfully!")

# Footer
st.divider()
st.markdown("""
<div style="text-align: center; color: #888; font-size: 0.9rem;">
    🛡️ Financial Resilience Agent | Powered by Ollama + LangChain<br>
    <a href="https://github.com/rheacisa/financial-resilience-agent" target="_blank">GitHub</a> | 
    Made with ❤️ for financial security
</div>
""", unsafe_allow_html=True)
