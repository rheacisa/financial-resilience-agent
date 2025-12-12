import streamlit as st
import json
import os
from datetime import datetime
import requests

# --- Configuration ---
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY") or st.secrets.get("ANTHROPIC_API_KEY", None)

# Available Claude models
CLAUDE_MODELS = {
    "claude-sonnet-4-20250514": "Claude Sonnet 4 (Best balance)",
    "claude-3-5-haiku-20241022": "Claude 3.5 Haiku (Fastest)",
    "claude-opus-4-20250514": "Claude Opus 4 (Most capable)",
}

# System prompt for security agent
SYSTEM_PROMPT = """You are a financial cyber resilience expert agent. You analyze security postures for financial institutions.

When analyzing, consider:
- Authentication mechanisms (MFA, SSO, password policies)
- Data protection (encryption, access controls)
- Compliance frameworks (PCI-DSS, SOC 2, GDPR, NIST CSF)
- Network security (WAF, firewalls, segmentation)
- Incident response readiness

Provide specific, actionable recommendations with risk levels (High/Medium/Low) and timelines.
Format your response with clear sections using markdown headers (###).
Be concise but thorough. Use bullet points and tables when helpful."""

# --- Claude (Anthropic) Integration ---
def query_claude(prompt, model="claude-sonnet-4-20250514", context=None):
    """Send a query to Anthropic Claude API and get response"""
    if not ANTHROPIC_API_KEY:
        return None
    
    try:
        system = SYSTEM_PROMPT
        if context:
            system += f"\n\nCurrent Security Profile:\n{context}"
        
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            },
            json={
                "model": model,
                "max_tokens": 2048,
                "system": system,
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            },
            timeout=60
        )
        
        if response.status_code == 200:
            return response.json()["content"][0]["text"]
        else:
            return f"Error: {response.status_code} - {response.text}"
    except Exception as e:
        return f"Error: {str(e)}"

def query_claude_streaming(prompt, model="claude-sonnet-4-20250514", context=None):
    """Send a query to Anthropic Claude API and stream the response"""
    if not ANTHROPIC_API_KEY:
        yield "Error: No Anthropic API key configured"
        return
    
    try:
        system = SYSTEM_PROMPT
        if context:
            system += f"\n\nCurrent Security Profile:\n{context}"
        
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json"
            },
            json={
                "model": model,
                "max_tokens": 2048,
                "system": system,
                "messages": [
                    {"role": "user", "content": prompt}
                ],
                "stream": True
            },
            stream=True,
            timeout=120
        )
        
        if response.status_code == 200:
            for line in response.iter_lines():
                if line:
                    line_text = line.decode('utf-8')
                    if line_text.startswith("data: "):
                        data_str = line_text[6:]
                        try:
                            data = json.loads(data_str)
                            if data.get("type") == "content_block_delta":
                                delta = data.get("delta", {})
                                if "text" in delta:
                                    yield delta["text"]
                        except json.JSONDecodeError:
                            continue
        else:
            yield f"Error: {response.status_code}"
    except Exception as e:
        yield f"Error: {str(e)}"

# --- Ollama Integration ---
def check_ollama_available():
    """Check if Ollama is running locally"""
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        return response.status_code == 200
    except:
        return False

def get_ollama_models():
    """Get list of available Ollama models"""
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=2)
        if response.status_code == 200:
            models = response.json().get("models", [])
            return [m["name"] for m in models]
    except:
        pass
    return []

def query_ollama_streaming(prompt, model="llama3.2", context=None):
    """Send a query to Ollama and stream the response"""
    try:
        system = SYSTEM_PROMPT
        if context:
            system += f"\n\nCurrent Security Profile:\n{context}"
        
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "system": system,
                "stream": True
            },
            stream=True,
            timeout=120
        )
        
        if response.status_code == 200:
            for line in response.iter_lines():
                if line:
                    data = json.loads(line)
                    if "response" in data:
                        yield data["response"]
                    if data.get("done", False):
                        break
    except Exception as e:
        yield f"Error: {str(e)}"

# Check availability at startup
OLLAMA_AVAILABLE = check_ollama_available()
OLLAMA_MODELS = get_ollama_models() if OLLAMA_AVAILABLE else []
CLAUDE_AVAILABLE = bool(ANTHROPIC_API_KEY)

# Determine active mode priority: Ollama (local/production) > Claude (cloud) > Simulation
if OLLAMA_AVAILABLE:
    ACTIVE_MODE = "ollama"
elif CLAUDE_AVAILABLE:
    ACTIVE_MODE = "claude"
else:
    ACTIVE_MODE = "simulation"

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

# Sidebar with INTERACTIVE inputs
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/security-checked--v1.png", width=80)
    st.title("⚙️ Configuration")
    
    st.subheader("📊 Your Security Profile")
    st.caption("Enter your organization's data:")
    
    # Interactive inputs that affect the dashboard
    mfa_coverage = st.slider("MFA Coverage (%)", 0, 100, 78, help="What % of accounts have MFA?")
    has_sso = st.toggle("SSO Enabled", value=True)
    has_encryption = st.toggle("Data Encryption at Rest", value=True)
    has_waf = st.toggle("Web Application Firewall", value=False)
    password_min_length = st.number_input("Password Min Length", 6, 24, 8)
    session_timeout = st.number_input("Session Timeout (min)", 5, 120, 30)
    
    st.divider()
    
    st.subheader("🏢 Organization")
    industry_sector = st.selectbox(
        "Industry Sector",
        ["Banking", "Insurance", "Investment", "Fintech", "Credit Union", "Other"]
    )
    
    num_employees = st.number_input("Number of Employees", 1, 100000, 250)
    annual_revenue = st.selectbox(
        "Annual Revenue",
        ["< $1M", "$1M - $10M", "$10M - $100M", "$100M - $1B", "> $1B"]
    )
    
    st.divider()
    
    st.subheader("🔒 Compliance")
    pci_compliant = st.toggle("PCI-DSS Certified", value=True)
    soc2_compliant = st.toggle("SOC 2 Certified", value=True)
    gdpr_compliant = st.toggle("GDPR Compliant", value=True)
    
    st.divider()
    
    # AI Model Status and Selection
    st.subheader("🤖 AI Engine")
    
    # Manual AI backend selector
    ai_options = {
        "1️⃣ Ollama (Local)": "ollama",
        "2️⃣ Claude (Anthropic)": "claude", 
        "3️⃣ Simulation (Demo)": "simulation"
    }
    
    selected_ai = st.selectbox(
        "Choose AI Backend",
        list(ai_options.keys()),
        index=1 if CLAUDE_AVAILABLE else (0 if OLLAMA_AVAILABLE else 2),
        help="Select which AI engine to use"
    )
    ai_mode = ai_options[selected_ai]
    
    # Show status and model selection based on choice
    if ai_mode == "ollama":
        if OLLAMA_AVAILABLE:
            st.success("✅ Ollama Connected")
            selected_model = st.selectbox(
                "Select Model",
                OLLAMA_MODELS if OLLAMA_MODELS else ["llama3.2"],
                help="Choose which local LLM to use"
            )
            st.caption("🏠 Running locally - production ready!")
        else:
            st.warning("⚠️ Ollama not running")
            st.caption("Start with: `ollama serve`")
            selected_model = None
    elif ai_mode == "claude":
        if CLAUDE_AVAILABLE:
            st.success("✅ Claude Connected")
            model_options = list(CLAUDE_MODELS.keys())
            model_labels = list(CLAUDE_MODELS.values())
            selected_idx = st.selectbox(
                "Select Model",
                range(len(model_options)),
                format_func=lambda i: model_labels[i],
                help="Choose which Claude model to use"
            )
            selected_model = model_options[selected_idx]
            st.caption("☁️ Claude AI - excellent for analysis!")
        else:
            st.warning("⚠️ No API key configured")
            st.caption("Add `ANTHROPIC_API_KEY` to secrets")
            selected_model = None
    else:
        st.info("🎭 Simulation Mode")
        st.caption("Demo responses - no AI backend needed")
        selected_model = None
    
    st.divider()
    st.caption("Built with Streamlit + LangChain")

# Calculate dynamic scores based on inputs
def calculate_risk_score():
    score = 50  # Base score
    
    # MFA impact
    score += (mfa_coverage - 50) * 0.3
    
    # Security controls
    if has_sso: score += 5
    if has_encryption: score += 10
    if has_waf: score += 8
    
    # Password policy
    if password_min_length >= 12: score += 5
    elif password_min_length >= 10: score += 3
    
    # Session management
    if session_timeout <= 15: score += 3
    elif session_timeout <= 30: score += 1
    
    return min(100, max(0, int(score)))

def get_risk_status(score):
    if score >= 80: return "Low"
    elif score >= 60: return "Medium"
    else: return "High"

overall_risk_score = calculate_risk_score()
overall_status = get_risk_status(overall_risk_score)

# Calculate category scores
network_score = 70 + (10 if has_waf else 0) + (5 if has_encryption else 0)
data_score = 50 + (20 if has_encryption else 0) + (10 if gdpr_compliant else 0)
access_score = 40 + int(mfa_coverage * 0.4) + (10 if has_sso else 0)
incident_score = 45 + (10 if soc2_compliant else 0)
thirdparty_score = 60 + (10 if pci_compliant else 0) + (8 if soc2_compliant else 0)

# Clamp scores
network_score = min(100, network_score)
data_score = min(100, data_score)
access_score = min(100, access_score)
incident_score = min(100, incident_score)
thirdparty_score = min(100, thirdparty_score)

# Count vulnerabilities based on gaps
vulnerabilities = 0
if mfa_coverage < 100: vulnerabilities += 3
if not has_waf: vulnerabilities += 5
if not has_encryption: vulnerabilities += 4
if password_min_length < 12: vulnerabilities += 2
if session_timeout > 30: vulnerabilities += 1
if not pci_compliant: vulnerabilities += 3
if not soc2_compliant: vulnerabilities += 2

# Main content area - using shorter tab labels for mobile
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(["📊 Dashboard", "🔍 Assess", "🔐 Security", "🏗️ Architecture", "📋 Reports", "❓ Help", "⚙️ Settings"])

with tab1:
    st.header("Security Overview")
    
    # Show hint to use sidebar
    st.info("👈 **Open sidebar** to input your organization's security data and see scores update in real-time!")
    
    # Metrics - 2x2 grid works better on mobile than 1x4
    col1, col2 = st.columns(2)
    
    with col1:
        delta_color = "normal" if overall_risk_score >= 70 else "inverse"
        st.metric(
            label="Risk Score",
            value=f"{overall_risk_score}/100",
            delta=f"{overall_status} Risk",
            delta_color="off"
        )
    
    with col2:
        st.metric(
            label="Vulnerabilities",
            value=str(vulnerabilities),
            delta=f"{vulnerabilities} found",
            delta_color="inverse" if vulnerabilities > 5 else "normal"
        )
    
    col3, col4 = st.columns(2)
    
    # Calculate compliance rate
    compliance_count = sum([pci_compliant, soc2_compliant, gdpr_compliant])
    compliance_rate = int((compliance_count / 3) * 100)
    
    with col3:
        st.metric(
            label="Compliance",
            value=f"{compliance_rate}%",
            delta="✓" if compliance_rate == 100 else f"{3-compliance_count} gaps",
            delta_color="normal" if compliance_rate >= 66 else "inverse"
        )
    
    with col4:
        st.metric(
            label="MFA Coverage",
            value=f"{mfa_coverage}%",
            delta="✓ Good" if mfa_coverage >= 90 else "↑ Improve",
            delta_color="normal" if mfa_coverage >= 90 else "off"
        )
    
    st.divider()
    
    # Risk categories - using calculated scores
    st.subheader("🎯 Risk Categories")
    risk_data = {
        "Network Security": {"score": network_score, "status": get_risk_status(network_score)},
        "Data Protection": {"score": data_score, "status": get_risk_status(data_score)},
        "Access Control": {"score": access_score, "status": get_risk_status(access_score)},
        "Incident Response": {"score": incident_score, "status": get_risk_status(incident_score)},
        "Third-Party Risk": {"score": thirdparty_score, "status": get_risk_status(thirdparty_score)},
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
    
    # Dynamic findings based on inputs
    st.subheader("🚨 Findings Based on Your Input")
    
    findings = []
    if mfa_coverage < 100:
        findings.append({"type": "Warning", "message": f"MFA only covers {mfa_coverage}% of accounts", "fix": "Enable MFA for all users"})
    if not has_waf:
        findings.append({"type": "Critical", "message": "No Web Application Firewall detected", "fix": "Deploy WAF to protect web apps"})
    if not has_encryption:
        findings.append({"type": "Critical", "message": "Data at rest is not encrypted", "fix": "Enable encryption for all databases"})
    if password_min_length < 12:
        findings.append({"type": "Warning", "message": f"Password length ({password_min_length}) below recommended 12 chars", "fix": "Update password policy"})
    if session_timeout > 30:
        findings.append({"type": "Info", "message": f"Session timeout ({session_timeout}min) is long", "fix": "Consider reducing to 15-30 min"})
    if not pci_compliant:
        findings.append({"type": "Critical", "message": "Not PCI-DSS compliant", "fix": "Prioritize PCI certification"})
    
    if not findings:
        st.success("✅ No critical findings! Your security posture looks good.")
    else:
        for finding in findings:
            icon = "🔴" if finding["type"] == "Critical" else "🟡" if finding["type"] == "Warning" else "🔵"
            with st.container():
                st.markdown(f"""
                <div class="alert-card">
                    {icon} <strong>{finding['type']}</strong><br>
                    <span style="color: #555;">{finding['message']}</span><br>
                    <span style="color: #1E3A5F;">💡 {finding['fix']}</span>
                </div>
                """, unsafe_allow_html=True)

with tab2:
    st.header("🤖 AI Agent Assessment")
    
    # Show mode indicator based on sidebar selection
    if ai_mode == "ollama" and OLLAMA_AVAILABLE:
        st.success("🟢 **Real AI Mode** - Ollama connected! Responses are generated by local LLM.")
        current_ai_mode = "ollama"
    elif ai_mode == "claude" and CLAUDE_AVAILABLE:
        st.success("☁️ **Cloud AI Mode** - Claude (Anthropic) connected! Responses are generated by cloud LLM.")
        current_ai_mode = "claude"
    elif ai_mode == "ollama" and not OLLAMA_AVAILABLE:
        st.warning("⚠️ **Ollama not available** - Start Ollama with `ollama serve` or select another backend.")
        current_ai_mode = "simulation"
    elif ai_mode == "claude" and not CLAUDE_AVAILABLE:
        st.warning("⚠️ **Claude not configured** - Add `ANTHROPIC_API_KEY` to secrets or select another backend.")
        current_ai_mode = "simulation"
    else:
        st.info("🔵 **Demo Mode** - Simulated agent responses for demonstration purposes.")
        current_ai_mode = "simulation"
    
    st.markdown("Enter your security question and watch the agent analyze it.")
    
    # Sample queries dropdown
    sample_queries = [
        "-- Select a sample query --",
        "Analyze our MFA implementation and identify gaps in coverage",
        "What are the risks of our current password policy requiring only 8 characters?",
        "Are we meeting PCI-DSS requirement 8.3 for multi-factor authentication?",
        "What's a good incident response plan for a data breach?",
        "Given our current security posture, what should we prioritize first?",
        "Create a 90-day security improvement roadmap based on our gaps",
    ]
    
    selected_sample = st.selectbox("💡 Try a sample query:", sample_queries)
    
    # Assessment input - full width for mobile
    default_query = selected_sample if selected_sample != "-- Select a sample query --" else ""
    assessment_query = st.text_area(
        "What would you like to assess?",
        value=default_query,
        placeholder="Example: Evaluate our authentication mechanisms...",
        height=120
    )
    
    # Checkboxes - stacked for mobile
    include_compliance = st.checkbox("✓ Include Compliance Check", value=True)
    include_recommendations = st.checkbox("✓ Generate Recommendations", value=True)
    show_reasoning = st.checkbox("👁️ Show Agent Reasoning (ReAct)", value=True)
    
    if st.button("🚀 Run Assessment", type="primary", use_container_width=True):
        if assessment_query:
            import time
            
            # Build context from sidebar inputs
            security_context = f"""
- Industry: {industry_sector}
- Employees: {num_employees}
- Annual Revenue: {annual_revenue}
- MFA Coverage: {mfa_coverage}%
- SSO Enabled: {has_sso}
- Data Encryption at Rest: {has_encryption}
- Web Application Firewall: {has_waf}
- Password Minimum Length: {password_min_length} characters
- Session Timeout: {session_timeout} minutes
- PCI-DSS Compliant: {pci_compliant}
- SOC 2 Compliant: {soc2_compliant}
- GDPR Compliant: {gdpr_compliant}
- Current Risk Score: {overall_risk_score}/100 ({overall_status} Risk)
"""
            
            # Build the full prompt (used by both Ollama and Claude)
            full_prompt = f"""Analyze this security question for a {industry_sector} organization:

**Question:** {assessment_query}

**Include in your analysis:**
1. Key findings based on their security profile
2. Risk assessment (High/Medium/Low) for each finding
{"3. Compliance implications (PCI-DSS, SOC 2, GDPR, NIST)" if include_compliance else ""}
{"4. Prioritized recommendations with timelines" if include_recommendations else ""}

Be specific and actionable. Reference their actual metrics where relevant."""

            # === REAL OLLAMA MODE ===
            if current_ai_mode == "ollama" and selected_model:
                st.subheader("🧠 Real Agent Reasoning")
                
                # Step 1: Analyze Query
                with st.status("🔄 Step 1: Analyzing your query...", expanded=True) as status:
                    st.markdown(f"**Query:** {assessment_query}")
                    st.markdown(f"**Model:** {selected_model}")
                    st.markdown(f"**Context:** Using your security profile from sidebar")
                    time.sleep(0.5)
                    status.update(label="Step 1: Query Analysis ✅", state="complete")
                
                # Step 2: Stream response from Ollama
                with st.status("🔄 Step 2: Agent reasoning with LLM...", expanded=True) as status:
                    st.markdown("**Sending to local LLM...**")
                    time.sleep(0.3)
                    status.update(label="Step 2: LLM Processing ✅", state="complete")
                
                st.subheader("📋 Agent Response")
                
                # Stream the response
                response_container = st.empty()
                full_response = ""
                
                with st.spinner("🤖 Generating response..."):
                    for chunk in query_ollama_streaming(full_prompt, selected_model, security_context):
                        full_response += chunk
                        response_container.markdown(full_response + "▌")
                
                response_container.markdown(full_response)
                
                # Agent Summary
                with st.expander("🤖 Agent Metadata"):
                    st.markdown(f"""
**Mode:** Real AI (Ollama - Local)
**Model:** {selected_model}
**Query:** {assessment_query[:100]}{'...' if len(assessment_query) > 100 else ''}
**Context Provided:** Security profile from sidebar
**Data Privacy:** ✅ All processing done locally - no data sent to cloud
                    """)
            
            # === CLAUDE CLOUD MODE ===
            elif current_ai_mode == "claude" and selected_model:
                st.subheader("☁️ Cloud Agent Reasoning")
                
                # Step 1: Analyze Query
                with st.status("🔄 Step 1: Analyzing your query...", expanded=True) as status:
                    st.markdown(f"**Query:** {assessment_query}")
                    st.markdown(f"**Model:** {CLAUDE_MODELS.get(selected_model, selected_model)}")
                    st.markdown(f"**Context:** Using your security profile from sidebar")
                    time.sleep(0.5)
                    status.update(label="Step 1: Query Analysis ✅", state="complete")
                
                # Step 2: Stream response from Claude
                with st.status("🔄 Step 2: Agent reasoning with Cloud LLM...", expanded=True) as status:
                    st.markdown("**Sending to Claude (Anthropic) API...**")
                    time.sleep(0.3)
                    status.update(label="Step 2: Cloud LLM Processing ✅", state="complete")
                
                st.subheader("📋 Agent Response")
                
                # Stream the response
                response_container = st.empty()
                full_response = ""
                
                with st.spinner("☁️ Generating response from Claude..."):
                    for chunk in query_claude_streaming(full_prompt, selected_model, security_context):
                        full_response += chunk
                        response_container.markdown(full_response + "▌")
                
                response_container.markdown(full_response)
                
                # Agent Summary
                with st.expander("🤖 Agent Metadata"):
                    st.markdown(f"""
**Mode:** Real AI (Claude - Anthropic)
**Model:** {CLAUDE_MODELS.get(selected_model, selected_model)}
**Query:** {assessment_query[:100]}{'...' if len(assessment_query) > 100 else ''}
**Context Provided:** Security profile from sidebar
**API:** Anthropic (console.anthropic.com)
                    """)
            
            # === SIMULATION MODE ===
            else:
                # Agent Reasoning Display
                if show_reasoning:
                    st.subheader("🧠 Agent Reasoning Process (Simulation)")
                    st.caption("ReAct Pattern: Reason → Act → Observe → Repeat")
                    
                    reasoning_container = st.container()
                    
                    with reasoning_container:
                        # Step 1: Parse Query
                        with st.status("🔄 Agent thinking...", expanded=True) as status:
                            st.markdown("**💭 Thought 1:** I need to analyze the user's security assessment request.")
                            time.sleep(0.8)
                            
                            st.markdown(f"**📝 Observation:** User wants to assess: *\"{assessment_query[:100]}{'...' if len(assessment_query) > 100 else ''}\"*")
                            time.sleep(0.5)
                            
                            st.markdown("**💭 Thought 2:** I should identify the key security domains involved.")
                            time.sleep(0.8)
                            
                            # Determine domains based on query
                            domains = []
                            query_lower = assessment_query.lower()
                            if any(word in query_lower for word in ['auth', 'login', 'password', 'mfa', '2fa']):
                                domains.append("Authentication & Access Control")
                            if any(word in query_lower for word in ['api', 'endpoint', 'token']):
                                domains.append("API Security")
                            if any(word in query_lower for word in ['data', 'encrypt', 'privacy']):
                                domains.append("Data Protection")
                            if any(word in query_lower for word in ['network', 'firewall', 'port']):
                                domains.append("Network Security")
                            if any(word in query_lower for word in ['compliance', 'pci', 'soc', 'gdpr']):
                                domains.append("Compliance")
                            if not domains:
                                domains = ["General Security Assessment"]
                            
                            st.markdown(f"**🎯 Identified Domains:** {', '.join(domains)}")
                            time.sleep(0.5)
                            
                            status.update(label="Step 1: Query Analysis ✅", state="complete")
                        
                        # Step 2: Tool Selection
                        with st.status("🔄 Selecting tools...", expanded=True) as status:
                            st.markdown("**💭 Thought 3:** Based on the domains, I need to select appropriate security tools.")
                            time.sleep(0.7)
                            
                            st.markdown("**🔧 Action:** Selecting tools from toolkit...")
                            time.sleep(0.5)
                            
                            tools_selected = [
                                "🔍 `vulnerability_scanner` - Check for known CVEs",
                                "🔐 `auth_analyzer` - Evaluate authentication mechanisms",
                                "📊 `compliance_checker` - Cross-reference with frameworks",
                                "🌐 `network_probe` - Assess network security posture"
                            ]
                            
                            for tool in tools_selected[:3]:  # Show 3 relevant tools
                                st.markdown(f"  • {tool}")
                                time.sleep(0.3)
                            
                            status.update(label="Step 2: Tool Selection ✅", state="complete")
                        
                        # Step 3: Execute Tools
                        with st.status("🔄 Running security scans...", expanded=True) as status:
                            st.markdown("**💭 Thought 4:** Now I'll execute each tool and collect findings.")
                            time.sleep(0.6)
                            
                            st.markdown(f"**🔧 Action:** `auth_analyzer.scan(target='customer_portal')`")
                            time.sleep(0.8)
                            st.markdown(f"**📝 Observation:** MFA coverage at {mfa_coverage}%, session timeout {session_timeout}min, {'SSO' if has_sso else 'no SSO'} detected")
                            time.sleep(0.5)
                            
                            st.markdown("**🔧 Action:** `vulnerability_scanner.check(scope='authentication')`")
                            time.sleep(0.8)
                            st.markdown(f"**📝 Observation:** {vulnerabilities} issues found based on current configuration")
                            time.sleep(0.5)
                            
                            if include_compliance:
                                st.markdown("**🔧 Action:** `compliance_checker.evaluate(frameworks=['PCI-DSS', 'SOC2'])`")
                                time.sleep(0.8)
                                pci_msg = "PCI-DSS compliant" if pci_compliant else "PCI-DSS gaps found"
                                soc2_msg = "SOC 2 compliant" if soc2_compliant else "SOC 2 gaps found"
                                st.markdown(f"**📝 Observation:** {pci_msg}, {soc2_msg}")
                                time.sleep(0.5)
                            
                            status.update(label="Step 3: Tool Execution ✅", state="complete")
                        
                        # Step 4: Synthesize
                        with st.status("🔄 Synthesizing results...", expanded=True) as status:
                            st.markdown("**💭 Thought 5:** I have all the data. Now I'll synthesize findings and generate recommendations.")
                            time.sleep(0.7)
                            
                            st.markdown("**🔧 Action:** Aggregating findings, calculating risk scores, prioritizing recommendations...")
                            time.sleep(0.8)
                            
                            st.markdown(f"**📝 Final Observation:** Assessment complete. Risk score: {overall_risk_score}/100.")
                            time.sleep(0.5)
                            
                            status.update(label="Step 4: Synthesis ✅", state="complete")
                    
                    st.divider()
                else:
                    with st.spinner("AI Agent analyzing your security posture..."):
                        time.sleep(2)
                
                st.success("✅ Assessment Complete (Simulation Mode)")
                
                # Results - Using actual sidebar inputs
                st.subheader("📋 Assessment Results")
                
                with st.expander("🔍 Findings (Based on Your Data)", expanded=True):
                    # Dynamic MFA finding
                    mfa_status = "🟢" if mfa_coverage >= 95 else "🟡" if mfa_coverage >= 70 else "🔴"
                    mfa_risk = "Low" if mfa_coverage >= 95 else "Medium" if mfa_coverage >= 70 else "High"
                    
                    # Dynamic password finding
                    pwd_status = "🟢" if password_min_length >= 12 else "🟡" if password_min_length >= 10 else "🔴"
                    pwd_risk = "Low" if password_min_length >= 12 else "Medium" if password_min_length >= 10 else "High"
                    
                    # Dynamic session finding
                    sess_status = "🟢" if session_timeout <= 30 else "🟡" if session_timeout <= 60 else "🔴"
                    sess_risk = "Low" if session_timeout <= 30 else "Medium" if session_timeout <= 60 else "High"
                    
                    st.markdown(f"""
### Key Findings

Based on your organization's security profile:

1. **Multi-Factor Authentication (MFA)** {mfa_status}
   - Current implementation covers **{mfa_coverage}%** of user accounts
   - {"✓ Excellent coverage!" if mfa_coverage >= 95 else "Gap: " + str(100-mfa_coverage) + "% of accounts unprotected"}
   - Risk Level: **{mfa_risk}**

2. **Password Policy** {pwd_status}
   - Minimum length: **{password_min_length} characters**
   - {"✓ Meets best practices" if password_min_length >= 12 else "⚠️ Below recommended 12 characters"}
   - Risk Level: **{pwd_risk}**

3. **Session Management** {sess_status}
   - Session timeout: **{session_timeout} minutes**
   - {"✓ Within recommended range" if session_timeout <= 30 else "⚠️ Consider reducing timeout"}
   - Risk Level: **{sess_risk}**

4. **Security Controls Summary**
   - SSO: {"✅ Enabled" if has_sso else "❌ Not enabled"}
   - Encryption at Rest: {"✅ Enabled" if has_encryption else "❌ Not enabled"}
   - WAF: {"✅ Deployed" if has_waf else "❌ Not deployed"}
                    """)
                
                if include_compliance:
                    with st.expander("📋 Compliance Status (Your Profile)"):
                        pci_status = "✅ Compliant" if pci_compliant else "❌ Non-compliant"
                        soc2_status = "✅ Compliant" if soc2_compliant else "❌ Non-compliant"
                        gdpr_status = "✅ Compliant" if gdpr_compliant else "❌ Non-compliant"
                        
                        # Calculate coverage based on inputs
                        pci_coverage = 60 + (20 if mfa_coverage >= 80 else 0) + (10 if has_encryption else 0) + (10 if password_min_length >= 12 else 0)
                        soc2_coverage = 70 + (15 if has_encryption else 0) + (15 if session_timeout <= 30 else 0)
                        gdpr_coverage = 65 + (20 if has_encryption else 0) + (15 if gdpr_compliant else 0)
                        
                        st.markdown(f"""
| Framework | Certification | Est. Coverage | Key Gap |
|-----------|---------------|---------------|---------|
| PCI-DSS | {pci_status} | {min(100, pci_coverage)}% | {"Req 8.3.1 - MFA" if mfa_coverage < 100 else "-"} |
| SOC 2 | {soc2_status} | {min(100, soc2_coverage)}% | {"CC6.1 - Encryption" if not has_encryption else "-"} |
| GDPR | {gdpr_status} | {min(100, gdpr_coverage)}% | {"-" if gdpr_compliant else "Art. 32 - Security"} |
| NIST CSF | ⚠️ Partial | {overall_risk_score}% | {"PR.AC-7 - Access" if access_score < 70 else "-"} |
                        """)
                
                if include_recommendations:
                    with st.expander("💡 Recommendations (Personalized)", expanded=True):
                        st.markdown("### 🎯 Priority Actions For Your Organization")
                        
                        recs = []
                        if mfa_coverage < 100:
                            priority = "🔴 High" if mfa_coverage < 80 else "🟡 Medium"
                            recs.append(f"| {priority} | Extend MFA to remaining {100-mfa_coverage}% of accounts | 14 days | +{int((100-mfa_coverage)*0.3)} pts |")
                        
                        if password_min_length < 12:
                            recs.append(f"| 🔴 High | Increase password minimum to 12 characters (currently {password_min_length}) | 7 days | +5 pts |")
                        
                        if not has_waf:
                            recs.append("| 🔴 High | Deploy Web Application Firewall | 30 days | +8 pts |")
                        
                        if not has_encryption:
                            recs.append("| 🔴 High | Enable data encryption at rest | 21 days | +10 pts |")
                        
                        if session_timeout > 30:
                            recs.append(f"| 🟡 Medium | Reduce session timeout from {session_timeout} to 30 min | 7 days | +3 pts |")
                        
                        if not has_sso:
                            recs.append("| 🟢 Low | Implement Single Sign-On (SSO) | 60 days | +5 pts |")
                        
                        if recs:
                            st.markdown("""
| Priority | Action | Timeline | Impact |
|----------|--------|----------|--------|
""" + "\n".join(recs))
                            
                            # Calculate projected improvement
                            potential_gain = 0
                            if mfa_coverage < 100: potential_gain += int((100-mfa_coverage)*0.3)
                            if password_min_length < 12: potential_gain += 5
                            if not has_waf: potential_gain += 8
                            if not has_encryption: potential_gain += 10
                            
                            new_score = min(100, overall_risk_score + potential_gain)
                            st.markdown(f"""
### 📊 Projected Improvement
Implementing all recommendations will improve your risk score from **{overall_risk_score} → {new_score}** (+{potential_gain} points)
                            """)
                        else:
                            st.success("🎉 Great job! No critical recommendations. Your security posture is strong.")
                
                # Agent Summary
                with st.expander("🤖 Agent Summary"):
                    st.markdown(f"""
**Mode:** Simulation (Ollama not connected)

**Query Analyzed:** {assessment_query[:150]}{'...' if len(assessment_query) > 150 else ''}

**Organization:** {industry_sector} | {num_employees} employees | {annual_revenue}

**Your Security Profile:**
- MFA Coverage: {mfa_coverage}%
- Password Policy: {password_min_length}+ chars
- Encryption: {"✅" if has_encryption else "❌"} | WAF: {"✅" if has_waf else "❌"} | SSO: {"✅" if has_sso else "❌"}

**Tools Used:** 3 (auth_analyzer, vulnerability_scanner, compliance_checker)

**Reasoning Steps:** 5

**Current Risk Score:** {overall_risk_score}/100 ({overall_status} Risk)

💡 *Run `ollama serve` locally for real AI-powered analysis!*
                    """)
        else:
            st.warning("Please describe what you'd like to assess.")

with tab3:
    st.header("🔐 Security Features")
    
    st.markdown("Comprehensive overview of security capabilities and controls evaluated by this agent.")
    
    # Authentication & Access Control
    st.subheader("🔑 Authentication & Access Control")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        **Multi-Factor Authentication (MFA)**
        - SMS/Email verification
        - Authenticator apps (TOTP)
        - Hardware security keys (FIDO2)
        - Biometric authentication
        - Risk-based adaptive MFA
        """)
    
    with col2:
        st.markdown("""
        **Single Sign-On (SSO)**
        - SAML 2.0 integration
        - OAuth 2.0 / OpenID Connect
        - Active Directory federation
        - Session management controls
        - Just-in-time provisioning
        """)
    
    st.divider()
    
    # Data Protection
    st.subheader("🛡️ Data Protection")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        **Encryption Standards**
        - AES-256 at rest
        - TLS 1.3 in transit
        - End-to-end encryption
        - Key management (HSM)
        - Certificate lifecycle
        """)
    
    with col2:
        st.markdown("""
        **Access Controls**
        - Role-based access (RBAC)
        - Attribute-based access (ABAC)
        - Least privilege principle
        - Data classification
        - DLP policies
        """)
    
    st.divider()
    
    # Network Security
    st.subheader("🌐 Network Security")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        **Perimeter Defense**
        - Web Application Firewall (WAF)
        - Next-gen firewalls (NGFW)
        - DDoS protection
        - Intrusion Detection (IDS/IPS)
        - Network segmentation
        """)
    
    with col2:
        st.markdown("""
        **Monitoring & Detection**
        - SIEM integration
        - 24/7 SOC monitoring
        - Threat intelligence feeds
        - Anomaly detection
        - Network flow analysis
        """)
    
    st.divider()
    
    # Compliance Frameworks
    st.subheader("📜 Compliance Frameworks")
    
    frameworks = {
        "PCI-DSS": "Payment Card Industry Data Security Standard - Required for organizations handling credit card data",
        "SOC 2": "Service Organization Control 2 - Trust service criteria for security, availability, and confidentiality",
        "GDPR": "General Data Protection Regulation - EU data privacy and protection requirements",
        "NIST CSF": "Cybersecurity Framework - Identify, Protect, Detect, Respond, Recover",
        "ISO 27001": "Information Security Management System - International security standard",
        "FFIEC": "Federal Financial Institutions Examination Council - US financial institution guidelines"
    }
    
    for framework, description in frameworks.items():
        with st.expander(f"✅ {framework}"):
            st.markdown(description)
    
    st.divider()
    
    # Incident Response
    st.subheader("🚨 Incident Response")
    
    st.markdown("""
    **Response Capabilities Evaluated:**
    
    | Phase | Key Activities |
    |-------|----------------|
    | **Preparation** | Playbooks, tabletop exercises, contact lists |
    | **Detection** | Alert triage, threat hunting, log analysis |
    | **Containment** | Isolation procedures, evidence preservation |
    | **Eradication** | Root cause analysis, malware removal |
    | **Recovery** | System restoration, monitoring enhancement |
    | **Lessons Learned** | Post-incident review, control improvements |
    """)
    
    st.divider()
    
    # Vulnerability Management
    st.subheader("🔍 Vulnerability Management")
    
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        **Assessment Types**
        - Automated vulnerability scans
        - Penetration testing
        - Code security reviews
        - Configuration audits
        - Third-party assessments
        """)
    
    with col2:
        st.markdown("""
        **Remediation Process**
        - Risk-based prioritization
        - SLA-driven patching
        - Compensating controls
        - Exception management
        - Verification testing
        """)

with tab4:
    st.header("🏗️ System Architecture")
    
    st.markdown("Understanding the agent design and technology choices.")
    
    # Architecture Overview
    st.subheader("📐 High-Level Architecture")
    
    st.markdown("""
```
┌─────────────────────────────────────────────────────────────────┐
│                      STREAMLIT UI LAYER                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │Dashboard │  │Assessment│  │ Reports  │  │    Settings      │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬─────────┘ │
└───────┼─────────────┼─────────────┼─────────────────┼───────────┘
        │             │             │                 │
        ▼             ▼             ▼                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    LANGCHAIN AGENT LAYER                        │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   ReAct Agent                           │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐              │    │
│  │  │  Reason  │→ │   Act    │→ │ Observe  │→ (repeat)    │    │
│  │  └──────────┘  └──────────┘  └──────────┘              │    │
│  └─────────────────────────────────────────────────────────┘    │
│                              │                                   │
│  ┌───────────────────────────┼───────────────────────────────┐  │
│  │                    TOOL REGISTRY                          │  │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────────────────┐ │  │
│  │  │VulnScanner │ │AuthAnalyzer│ │  ComplianceChecker     │ │  │
│  │  └────────────┘ └────────────┘ └────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    LOCAL LLM LAYER (OLLAMA)                     │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │   Llama 3.2 / Mistral / CodeLlama (On-Premise)          │    │
│  │   🔒 Data never leaves your infrastructure              │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```
    """)
    
    st.divider()
    
    # Why Local LLMs
    st.subheader("🔒 Why Local LLMs for Finance?")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
### ❌ Cloud LLM Risks
        
| Risk | Impact |
|------|--------|
| **Data Exfiltration** | Sensitive data sent to third-party |
| **Compliance Violation** | PCI-DSS, SOC 2 require data controls |
| **Vendor Lock-in** | Dependent on API availability |
| **Cost at Scale** | Token costs grow exponentially |
| **Latency** | Network round-trips add delay |
        """)
    
    with col2:
        st.markdown("""
### ✅ Local LLM Benefits
        
| Benefit | Impact |
|---------|--------|
| **Data Sovereignty** | All data stays on-premise |
| **Regulatory Compliance** | Meets financial data requirements |
| **No API Costs** | Fixed infrastructure cost |
| **Low Latency** | Sub-100ms inference |
| **Customizable** | Fine-tune on proprietary data |
        """)
    
    st.divider()
    
    # Technology Stack
    st.subheader("🛠️ Technology Stack")
    
    st.markdown("""
| Component | Technology | Why This Choice |
|-----------|------------|------------------|
| **UI Framework** | Streamlit | Rapid prototyping, Python-native, great for data apps |
| **Agent Framework** | LangChain | Industry standard, extensive tool ecosystem, ReAct support |
| **Local LLM** | Ollama | Easy deployment, supports multiple models, REST API |
| **Models** | Llama 3.2, Mistral | Open-source, strong reasoning, no license restrictions |
| **Deployment** | Docker/K8s | Containerized, scalable, enterprise-ready |
    """)
    
    st.divider()
    
    # Agent Design Pattern
    st.subheader("🤖 Agent Design: ReAct Pattern")
    
    st.markdown("""
The agent uses the **ReAct (Reason + Act)** pattern, which combines:

1. **Reasoning** - The LLM thinks about what to do next
2. **Acting** - The agent calls a tool with specific parameters  
3. **Observing** - The agent sees the tool's output
4. **Iterating** - Repeat until task is complete

```python
# Simplified ReAct Loop
while not task_complete:
    thought = llm.reason(query, observations)     # 💭 Think
    action = agent.select_tool(thought)           # 🔧 Choose tool
    observation = action.execute()                # 📝 Get result
    observations.append(observation)              # 🔄 Update context
```

**Why ReAct for Security?**
- ✅ Explainable decisions (audit trail)
- ✅ Can use specialized security tools
- ✅ Breaks complex assessments into steps
- ✅ Self-correcting through observation
    """)
    
    st.divider()
    
    # Security Tools
    st.subheader("🔧 Security Tool Registry")
    
    tools = [
        {"name": "vulnerability_scanner", "desc": "Scans for CVEs and known vulnerabilities", "api": "scan(target, scope)"},
        {"name": "auth_analyzer", "desc": "Evaluates authentication mechanisms", "api": "analyze(auth_type, config)"},
        {"name": "compliance_checker", "desc": "Checks against regulatory frameworks", "api": "check(frameworks[])"},
        {"name": "network_probe", "desc": "Assesses network security posture", "api": "probe(ip_range, ports)"},
        {"name": "log_analyzer", "desc": "Analyzes security logs for anomalies", "api": "analyze(log_source, timeframe)"},
    ]
    
    for tool in tools:
        with st.expander(f"🔧 `{tool['name']}`"):
            st.markdown(f"**Description:** {tool['desc']}")
            st.code(f"{tool['name']}.{tool['api']}", language="python")
    
    st.divider()
    
    # Edge Deployment
    st.subheader("🌐 Edge Deployment Architecture")
    
    st.markdown("""
```
                    ┌─────────────────┐
                    │  CENTRAL SIEM   │
                    │  (Aggregation)  │
                    └────────┬────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
         ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│   BRANCH A      │ │   BRANCH B      │ │   BRANCH C      │
│ ┌─────────────┐ │ │ ┌─────────────┐ │ │ ┌─────────────┐ │
│ │ Local Agent │ │ │ │ Local Agent │ │ │ │ Local Agent │ │
│ │ + Ollama    │ │ │ │ + Ollama    │ │ │ │ + Ollama    │ │
│ └─────────────┘ │ │ └─────────────┘ │ │ └─────────────┘ │
│  🔒 Data Local  │ │  🔒 Data Local  │ │  🔒 Data Local  │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

**Benefits of Edge Deployment:**
- Each branch processes data locally (data sovereignty)
- Central aggregation for enterprise-wide visibility
- Resilient to network outages
- Reduced bandwidth costs
    """)

with tab5:
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

with tab6:
    st.header("❓ Help & Setup")
    
    # Current Mode Status
    st.subheader("🔌 Current Mode")
    if OLLAMA_AVAILABLE:
        st.success("✅ **Real AI Mode** - Ollama is connected and running!")
        st.markdown(f"**Models available:** {', '.join(OLLAMA_MODELS) if OLLAMA_MODELS else 'llama3.2'}")
    else:
        st.info("🔵 **Demo Mode** - Using simulation. Responses are based on your sidebar inputs.")
        st.markdown("To enable real AI, install and run Ollama locally (see below).")
    
    st.divider()
    
    # Sample Queries
    st.subheader("💬 Sample Queries to Try")
    
    queries = {
        "🔐 Authentication": [
            "Analyze our MFA implementation and identify gaps",
            "What are the risks of 8-character passwords?",
            "How can we improve session management?",
        ],
        "📋 Compliance": [
            "Are we meeting PCI-DSS requirement 8.3?",
            "What SOC 2 controls are we missing?",
            "Generate a GDPR compliance checklist",
        ],
        "📊 Risk Assessment": [
            "What should we prioritize first?",
            "Create a 90-day security roadmap",
            "What's the business impact of ransomware?",
        ],
        "🚨 Incident Response": [
            "What's a good incident response plan for a breach?",
            "What should we do in the first 24 hours of a breach?",
            "Create a ransomware response playbook",
        ],
    }
    
    for category, query_list in queries.items():
        with st.expander(category):
            for q in query_list:
                st.code(q, language=None)
    
    st.divider()
    
    # How to Use
    st.subheader("📖 How to Use This App")
    
    st.markdown("""
    **Step 1: Configure Your Profile**
    - Open the sidebar (click `>` top-left)
    - Enter your organization's security settings
    - Watch the dashboard update in real-time
    
    **Step 2: Run an Assessment**
    - Go to the **🔍 Assess** tab
    - Select a sample query or type your own
    - Click **Run Assessment**
    - View the agent's reasoning and recommendations
    
    **Step 3: Review Results**
    - Findings are personalized to YOUR inputs
    - Recommendations include timelines and impact scores
    - Use these for your security roadmap
    """)
    
    st.divider()
    
    # Local Setup Instructions
    st.subheader("🖥️ Run With Real AI (Local Setup)")
    
    st.markdown("To enable real AI-powered responses, run Ollama locally:")
    
    with st.expander("📦 Installation Instructions", expanded=False):
        st.markdown("""
        **1. Install Ollama**
        """)
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown("**Mac**")
            st.code("brew install ollama", language="bash")
        with col2:
            st.markdown("**Linux**")
            st.code("curl -fsSL https://ollama.com/install.sh | sh", language="bash")
        with col3:
            st.markdown("**Windows**")
            st.markdown("[Download installer](https://ollama.com/download)")
        
        st.markdown("""
        **2. Download a Model**
        """)
        st.code("ollama pull llama3.2", language="bash")
        
        st.markdown("""
        **3. Start Ollama**
        """)
        st.code("ollama serve", language="bash")
        
        st.markdown("""
        **4. Run the App Locally**
        """)
        st.code("""git clone https://github.com/rheacisa/financial-resilience-agent
cd financial-resilience-agent
pip install -r requirements.txt
streamlit run app.py""", language="bash")
        
        st.success("Once Ollama is running, refresh this page to see '✅ Real AI Mode'!")
    
    st.divider()
    
    # FAQ
    st.subheader("🤔 FAQ")
    
    with st.expander("What is an agent vs a chatbot?"):
        st.markdown("""
        A **chatbot** just responds to prompts. An **agent** has autonomy - it can:
        - Reason about a task
        - Decide which tools to use
        - Execute tools and observe results
        - Iterate until the task is complete
        
        This app uses the **ReAct pattern**: Reason → Act → Observe → Repeat
        """)
    
    with st.expander("Why use local LLMs instead of OpenAI?"):
        st.markdown("""
        **For financial institutions:**
        - 🔒 **Data Sovereignty** - Sensitive data never leaves your infrastructure
        - 📋 **Compliance** - Meets PCI-DSS, SOC 2, GDPR requirements
        - 💰 **Cost** - No per-token API costs
        - ⚡ **Latency** - Faster responses without network round-trips
        """)
    
    with st.expander("Is the demo using real AI?"):
        st.markdown(f"""
        **Current mode:** {"✅ Real AI (Ollama)" if OLLAMA_AVAILABLE else "🔵 Simulation"}
        
        {"The app is connected to Ollama and generating real AI responses!" if OLLAMA_AVAILABLE else "The cloud demo uses simulation - responses are based on your sidebar inputs, not actual AI reasoning. Run locally with Ollama for real AI!"}
        """)
    
    with st.expander("What would you add next?"):
        st.markdown("""
        **Roadmap ideas:**
        1. **RAG** - Connect to internal security documentation
        2. **Real integrations** - Pull from Nessus, Qualys, SIEM logs
        3. **Multi-agent** - Separate agents for network, identity, compliance
        4. **Automated remediation** - Execute fixes, not just recommend
        """)

with tab7:
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
