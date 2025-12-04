import streamlit as st
import json
from datetime import datetime

# Page configuration - use centered layout for better mobile experience
st.set_page_config(
    page_title="Financial Resilience Agent",
    page_icon="🛡️",
    layout="centered",  # Better for mobile
    initial_sidebar_state="collapsed"  # Collapsed by default on mobile
)

# Mobile-friendly CSS with responsive design
st.markdown("""
<style>
    /* Responsive header */
    .main-header {
        font-size: clamp(1.5rem, 5vw, 2.5rem);
        font-weight: bold;
        color: #1E3A5F;
        text-align: center;
        margin-bottom: 0.5rem;
        padding: 0 1rem;
    }
    .sub-header {
        font-size: clamp(0.9rem, 3vw, 1.2rem);
        color: #4A6FA5;
        text-align: center;
        margin-bottom: 1.5rem;
        padding: 0 1rem;
    }
    
    /* Mobile-friendly metric cards */
    .metric-card {
        background-color: #f0f2f6;
        border-radius: 10px;
        padding: 1rem;
        margin: 0.5rem 0;
    }
    
    /* Risk status colors */
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
    
    /* Mobile-friendly buttons - larger touch targets */
    .stButton > button {
        min-height: 48px;
        font-size: 1rem;
        padding: 0.5rem 1rem;
    }
    
    /* Better spacing on mobile */
    .block-container {
        padding-top: 1rem;
        padding-bottom: 1rem;
        max-width: 100%;
    }
    
    /* Responsive tabs */
    .stTabs [data-baseweb="tab-list"] {
        gap: 0.5rem;
        flex-wrap: wrap;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 0.5rem 0.75rem;
        font-size: clamp(0.8rem, 2.5vw, 1rem);
    }
    
    /* Mobile-friendly inputs */
    .stTextArea textarea, .stTextInput input, .stSelectbox select {
        font-size: 16px !important; /* Prevents zoom on iOS */
    }
    
    /* Better checkbox/toggle touch targets */
    .stCheckbox {
        padding: 0.5rem 0;
    }
    
    /* Responsive columns on mobile */
    @media (max-width: 768px) {
        [data-testid="column"] {
            width: 100% !important;
            flex: 1 1 100% !important;
            min-width: 100% !important;
        }
        
        /* Stack metrics vertically on mobile */
        [data-testid="stMetricValue"] {
            font-size: 1.5rem;
        }
        
        /* Better spacing for mobile */
        .element-container {
            margin-bottom: 0.5rem;
        }
    }
    
    /* Alert cards - better mobile display */
    .alert-card {
        background: #f8f9fa;
        border-radius: 8px;
        padding: 0.75rem;
        margin: 0.5rem 0;
        border-left: 4px solid #1E3A5F;
    }
    
    /* Hide sidebar toggle hint on mobile */
    @media (max-width: 768px) {
        [data-testid="collapsedControl"] {
            display: block;
        }
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

# Main content area - using shorter tab labels for mobile
tab1, tab2, tab3, tab4 = st.tabs(["📊 Dashboard", "🔍 Assess", "📋 Reports", "⚙️ Settings"])

with tab1:
    st.header("Security Overview")
    
    # Metrics - 2x2 grid works better on mobile than 1x4
    col1, col2 = st.columns(2)
    
    with col1:
        st.metric(
            label="Risk Score",
            value="72/100",
            delta="-5",
            delta_color="normal"
        )
    
    with col2:
        st.metric(
            label="Vulnerabilities",
            value="23",
            delta="3 new",
            delta_color="inverse"
        )
    
    col3, col4 = st.columns(2)
    
    with col3:
        st.metric(
            label="Compliance",
            value="94%",
            delta="2%",
            delta_color="normal"
        )
    
    with col4:
        st.metric(
            label="Last Scan",
            value="2d ago",
            delta=None
        )
    
    st.divider()
    
    # Risk categories - single column for mobile, stacked layout
    st.subheader("🎯 Risk Categories")
    risk_data = {
        "Network Security": {"score": 85, "status": "Low"},
        "Data Protection": {"score": 72, "status": "Medium"},
        "Access Control": {"score": 68, "status": "Medium"},
        "Incident Response": {"score": 45, "status": "High"},
        "Third-Party Risk": {"score": 78, "status": "Low"},
    }
    
    for category, data in risk_data.items():
        status_class = f"risk-{data['status'].lower()}"
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown(f"**{category}**")
            st.progress(data['score'] / 100)
        with col2:
            st.markdown(f"<span class='{status_class}'>{data['status']}</span>", unsafe_allow_html=True)
    
    st.divider()
    
    # Recent Alerts - mobile-friendly cards
    st.subheader("🚨 Recent Alerts")
    alerts = [
        {"time": "2h ago", "type": "Warning", "message": "Unusual login pattern detected"},
        {"time": "5h ago", "type": "Info", "message": "Security patch available"},
        {"time": "1d ago", "type": "Critical", "message": "Failed auth attempts exceeded"},
        {"time": "2d ago", "type": "Info", "message": "Compliance report generated"},
    ]
    
    for alert in alerts:
        icon = "🔴" if alert["type"] == "Critical" else "🟡" if alert["type"] == "Warning" else "🔵"
        with st.container():
            st.markdown(f"""
            <div class="alert-card">
                {icon} <strong>{alert['type']}</strong> · {alert['time']}<br>
                <span style="color: #555;">{alert['message']}</span>
            </div>
            """, unsafe_allow_html=True)

with tab2:
    st.header("Run Assessment")
    
    st.markdown("Analyze your infrastructure's cyber resilience with AI.")
    
    # Assessment input - full width for mobile
    assessment_query = st.text_area(
        "What would you like to assess?",
        placeholder="Example: Evaluate our authentication mechanisms...",
        height=120
    )
    
    # Checkboxes - stacked for mobile
    include_compliance = st.checkbox("✓ Include Compliance Check", value=True)
    include_recommendations = st.checkbox("✓ Generate Recommendations", value=True)
    
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
    st.header("Reports")
    
    st.markdown("View and download previous assessments.")
    
    # Sample reports - mobile-friendly card layout
    reports = [
        {"date": "2024-12-01", "type": "Full Security Audit", "status": "Completed", "score": 72},
        {"date": "2024-11-15", "type": "Vulnerability Scan", "status": "Completed", "score": 78},
        {"date": "2024-11-01", "type": "Compliance Check", "status": "Completed", "score": 85},
        {"date": "2024-10-15", "type": "Incident Response", "status": "Completed", "score": 65},
    ]
    
    for report in reports:
        with st.container():
            st.markdown(f"""
            **📄 {report['type']}**  
            📅 {report['date']} · Score: {report['score']}/100 · ✅ {report['status']}
            """)
            st.button("📥 Download", key=f"download_{report['date']}", use_container_width=True)
            st.divider()

with tab4:
    st.header("Settings")
    
    # Single column layout for mobile - all stacked
    st.subheader("🔔 Notifications")
    st.checkbox("Email alerts for critical findings", value=True)
    st.checkbox("Weekly summary reports", value=True)
    st.checkbox("Real-time vulnerability notifications", value=False)
    
    st.divider()
    
    st.subheader("🔑 API Configuration")
    st.text_input("API Endpoint", value="https://api.example.com/v1", disabled=True)
    st.text_input("API Key", type="password", placeholder="Enter your API key")
    
    st.divider()
    
    st.subheader("📊 Assessment Defaults")
    st.slider("Risk Threshold", 0, 100, 70)
    st.multiselect(
        "Compliance Frameworks",
        ["PCI-DSS", "SOC 2", "GDPR", "NIST CSF", "ISO 27001"],
        default=["PCI-DSS", "SOC 2"]
    )
    
    st.divider()
    
    st.subheader("💾 Data Retention")
    st.selectbox("Keep reports for", ["30 days", "90 days", "1 year", "Forever"])
    
    st.divider()
    
    st.button("💾 Save Settings", type="primary", use_container_width=True)

# Footer - mobile friendly
st.divider()
st.markdown("""
<div style="text-align: center; color: #888; font-size: 0.85rem; padding: 1rem 0;">
    🛡️ Financial Resilience Agent<br>
    Powered by Ollama + LangChain<br>
    <a href="https://github.com/rheacisa/financial-resilience-agent" target="_blank">GitHub</a>
</div>
""", unsafe_allow_html=True)
