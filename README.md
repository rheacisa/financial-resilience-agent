# 🛡️ Financial Cyber Resilience AI Agent

**Edge-deployed AI agent for assessing financial institution resilience against cyber threats and operational risks.**

🚀 **No cloud required** - Runs locally using Ollama (Mistral 7B) + LangChain

> **Inspired by:** Kudzai Manditereza's [Industrial AI Agent Architecture](https://github.com/kmanditereza) - Adapted for financial sector cybersecurity and regulatory compliance

---

## 📋 Overview

This AI agent helps financial institutions assess their resilience to cyber threats and operational risks by:

- 🏦 Monitoring financial health metrics and regulatory compliance (Capital Adequacy, Liquidity Coverage)
- 🔒 Analyzing cybersecurity posture and threat landscape
- 📖 Providing incident response playbooks for ransomware, data breaches, and liquidity crises
- 💡 Recommending recovery actions based on current state
- ⚖️ Ensuring regulatory compliance (OCC, FDIC, SEC, GDPR)

The agent operates entirely **on-premises** using local LLMs via Ollama - no sensitive data leaves your network.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    USER INPUT / QUERY                        │
│              "Assess ransomware preparedness"                │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                  PROMPT TEMPLATE                             │
│   Financial Cyber Resilience Agent Instructions              │
│   - Regulatory thresholds (CAR 10.5%, LCR 100%)             │
│   - Risk level definitions (STABLE/AT_RISK/CRITICAL)        │
│   - Analysis approach and tool usage guidance                │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│            AI AGENT (Python + LangChain)                     │
│   - Orchestrates tool calls                                  │
│   - Performs reasoning and analysis                          │
│   - Structures recommendations                               │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│          LOCAL LLM (Mistral via Ollama)                      │
│   - Planning and reasoning (replaces cloud Claude)           │
│   - Natural language understanding                           │
│   - Decision synthesis                                       │
│   - Base URL: http://localhost:11434                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                      TOOLS                                   │
│  ┌──────────────────┐  ┌─────────────────┐                 │
│  │ Financial        │  │ Threat Intel    │                 │
│  │ Metrics          │  │ Feed            │                 │
│  │ - CAR, LCR       │  │ - Threat levels │                 │
│  │ - Cyber score    │  │ - Vulns, CVEs   │                 │
│  │ - Trust index    │  │ - FS-ISAC/CISA  │                 │
│  └──────────────────┘  └─────────────────┘                 │
│  ┌──────────────────┐  ┌─────────────────┐                 │
│  │ Incident         │  │ Simulation &    │                 │
│  │ Playbooks        │  │ Recovery        │                 │
│  │ - Ransomware     │  │ - Attack models │                 │
│  │ - Data breach    │  │ - Recovery acts │                 │
│  │ - Liquidity      │  │ - Impact calc   │                 │
│  └──────────────────┘  └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│              STRUCTURED RESPONSE                             │
│   - Risk level (STABLE/AT_RISK/CRITICAL)                    │
│   - Decision and reasoning                                   │
│   - Recommended actions                                      │
│   - Regulatory concerns                                      │
│   - Metrics summary                                          │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

**1. Install Ollama**

```bash
# macOS
brew install ollama

# Linux
curl -fsSL https://ollama.com/install.sh | sh

# Windows
# Download from https://ollama.com/download
```

**2. Start Ollama Service**

```bash
ollama serve
```

**3. Pull Mistral Model**

```bash
ollama pull mistral
```

### Installation

**1. Clone the Repository**

```bash
git clone https://github.com/rheacisa/financial-resilience-agent.git
cd financial-resilience-agent
```

**2. Create Virtual Environment**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

**3. Install Dependencies**

```bash
pip install -r requirements.txt
```

### Running the Agent

**Option 1: CLI Interface**

```bash
python main.py
```

**Option 2: Streamlit Web UI**

```bash
streamlit run app.py
```

The web interface will open at `http://localhost:8501`

---

## 💬 Example Queries

Try these queries with the agent:

1. **"What is the current resilience status of our financial institution?"**
   - Gets comprehensive assessment of all metrics and compliance status

2. **"Assess our preparedness for a ransomware attack"**
   - Analyzes current defenses, retrieves ransomware playbook, recommends improvements

3. **"What would happen if we experienced a data breach?"**
   - Simulates impact on trust and capital, outlines notification requirements (GDPR 72h, SEC 4 days)

4. **"Are we in compliance with regulatory requirements?"**
   - Checks Capital Adequacy Ratio (≥10.5%), Liquidity Coverage Ratio (≥100%), and other thresholds

5. **"Simulate a DDoS attack and recommend recovery actions"**
   - Models availability impact, calculates financial loss, suggests DR activation

---

## 📁 Project Structure

```
financial-resilience-agent/
│
├── main.py                  # Agent logic & CLI interface
│   ├── ResilienceAssessmentResponse (Pydantic model)
│   ├── create_resilience_agent() - Agent initialization
│   ├── extract_json_from_response() - Response parsing
│   └── display_assessment() - Pretty printing
│
├── financial_system.py      # Simulated financial metrics
│   ├── FinancialSystemState (dataclass)
│   ├── get_financial_metrics() - Current state
│   ├── simulate_cyber_attack() - Impact modeling
│   ├── apply_recovery_action() - Recovery simulation
│   └── reset_system() - Restore baseline
│
├── threat_intel.py          # Threat intelligence feed
│   ├── get_current_threat_level() - Threat landscape
│   ├── get_vulnerability_status() - CVE/patch data
│   └── get_industry_alerts() - FS-ISAC/CISA alerts
│
├── playbooks.py             # Incident response procedures
│   ├── PLAYBOOKS dict - Ransomware, data breach, liquidity, DR
│   ├── get_playbook() - Retrieve specific playbook
│   └── calculate_recovery_impact() - Project outcomes
│
├── tools.py                 # LangChain tool wrappers
│   ├── get_financial_metrics_tool
│   ├── get_threat_intelligence_tool
│   ├── get_incident_playbook_tool
│   ├── simulate_attack_impact_tool
│   ├── calculate_recovery_outlook_tool
│   └── apply_recovery_action_tool
│
├── app.py                   # Streamlit web UI
│   ├── System status sidebar (live metrics)
│   ├── Chat interface with agent
│   ├── Quick action buttons (simulate attacks/recovery)
│   └── Formatted assessment display
│
├── requirements.txt         # Python dependencies
├── .gitignore              # Git ignore patterns
├── .env.example            # Environment variables template
└── README.md               # This file
```

---

## ⚙️ Configuration

### Switching LLM Providers

By default, the agent uses **Ollama with Mistral**. To use cloud LLMs:

**1. Create `.env` file from template:**

```bash
cp .env.example .env
```

**2. Add your API key:**

```env
# For Anthropic Claude
ANTHROPIC_API_KEY=your_key_here

# OR for OpenAI GPT-4
OPENAI_API_KEY=your_key_here
```

**3. Uncomment alternative LLM in `main.py`:**

```python
# For Anthropic Claude
from langchain_anthropic import ChatAnthropic
llm = ChatAnthropic(
    model="claude-3-5-sonnet-20241022",
    temperature=0.1,
    api_key=os.getenv("ANTHROPIC_API_KEY")
)

# OR for OpenAI GPT-4
from langchain_openai import ChatOpenAI
llm = ChatOpenAI(
    model="gpt-4-turbo-preview",
    temperature=0.1,
    api_key=os.getenv("OPENAI_API_KEY")
)
```

---

## 🎓 Resume Value

This project demonstrates practical experience with:

| Skill Area | Technologies/Concepts |
|------------|----------------------|
| **AI/ML Engineering** | LangChain, LLM orchestration, prompt engineering, tool calling |
| **Financial Domain** | Regulatory compliance (Basel III, OCC, FDIC), capital adequacy, liquidity ratios |
| **Cybersecurity** | Threat intelligence, incident response, MITRE ATT&CK, vulnerability management |
| **Risk Management** | Risk assessment frameworks, impact modeling, recovery planning |
| **Regulatory Tech** | GDPR (72h), SEC (4 days), banking regulations, notification requirements |
| **Software Engineering** | Python, Pydantic, type hints, modular architecture |
| **UI Development** | Streamlit, interactive dashboards, real-time metrics |
| **Edge Computing** | On-premises deployment, local LLM inference, no cloud dependencies |
| **API Design** | Tool interfaces, structured outputs, error handling |

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Kudzai Manditereza** - For the inspiring [Industrial AI Agent architecture](https://github.com/kmanditereza) that served as the foundation for this financial sector adaptation
- **Ollama Team** - For making local LLM inference accessible and efficient
- **LangChain** - For the excellent agent orchestration framework
- **Financial Services ISAC (FS-ISAC)** - For threat intelligence sharing in the financial sector
- **CISA** - For cybersecurity guidance and alert frameworks

---

## 📧 Contact

For questions or contributions, please open an issue on GitHub.

**Built for financial institutions prioritizing data privacy and edge deployment** 🛡️
