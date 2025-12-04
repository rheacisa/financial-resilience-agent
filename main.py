"""
Financial Cyber Resilience AI Agent - Main Entry Point

This agent assesses financial institution resilience against cyber threats
and operational risks using local LLM (Ollama with Mistral) and LangChain.
"""

import json
import re
import os
from typing import Dict, Any, List
from pydantic import BaseModel, Field

# LangChain imports
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.prebuilt import create_react_agent

# Optional cloud LLM imports (commented out by default)
# from langchain_anthropic import ChatAnthropic
# from langchain_openai import ChatOpenAI

# Import our tools
from tools import ALL_TOOLS


class ResilienceAssessmentResponse(BaseModel):
    """Structured response from resilience assessment"""
    risk_level: str = Field(description="Overall risk level: STABLE, AT_RISK, or CRITICAL")
    decision: str = Field(description="Primary decision or recommendation")
    reasoning: str = Field(description="Detailed reasoning behind the assessment")
    current_metrics_summary: Dict[str, str] = Field(description="Summary of current financial and cyber metrics")
    threat_assessment: str = Field(description="Assessment of current threat landscape")
    recommended_actions: List[str] = Field(description="List of recommended actions")
    regulatory_concerns: List[str] = Field(description="Any regulatory compliance concerns")
    tools_used: List[str] = Field(description="List of tools used in analysis")


def create_resilience_agent(verbose: bool = True):
    """
    Create the Financial Cyber Resilience Agent
    
    Args:
        verbose: Whether to show agent reasoning process
    
    Returns:
        Configured agent executor
    """
    
    # Initialize LLM - Default to Ollama (local)
    llm = ChatOllama(
        model="mistral",
        temperature=0.1,
        base_url="http://localhost:11434"
    )
    
    # Alternative LLM configurations (commented out)
    # For Anthropic Claude:
    # llm = ChatAnthropic(
    #     model="claude-3-5-sonnet-20241022",
    #     temperature=0.1,
    #     api_key=os.getenv("ANTHROPIC_API_KEY")
    # )
    
    # For OpenAI GPT-4:
    # llm = ChatOpenAI(
    #     model="gpt-4-turbo-preview",
    #     temperature=0.1,
    #     api_key=os.getenv("OPENAI_API_KEY")
    # )
    
    # Create comprehensive system message
    system_message = """You are a Financial Cyber Resilience Agent specialized in assessing financial institutions' resilience against cyber threats and operational risks.

Your mission is to provide comprehensive risk assessments by analyzing:
- Financial health metrics and regulatory compliance
- Cybersecurity threat landscape and vulnerabilities  
- Incident response preparedness
- Recovery capabilities

KEY REGULATORY THRESHOLDS (CRITICAL - ALWAYS CHECK):
- Capital Adequacy Ratio: Minimum 10.5% (regulatory requirement)
- Liquidity Coverage Ratio: Minimum 100% (regulatory requirement)
- Cyber Resilience Score: Target 80+ (best practice)
- Customer Trust Index: Target 90+ (best practice)

RISK LEVEL DEFINITIONS:
- STABLE: All metrics meet/exceed thresholds, threat level manageable
- AT_RISK: One or more metrics below threshold OR elevated threat environment
- CRITICAL: Multiple regulatory violations OR critical threats OR active incidents

ANALYSIS APPROACH:
1. ALWAYS start by gathering current metrics using get_financial_metrics_tool
2. Assess threat environment using get_threat_intelligence_tool
3. For incident scenarios, retrieve relevant playbooks using get_incident_playbook_tool
4. Only use simulate_attack_impact_tool when explicitly asked to model "what-if" scenarios
5. Recommend recovery actions based on current state

RESPONSE STRUCTURE:
Your response should be comprehensive but clear, including:
- Risk level (STABLE/AT_RISK/CRITICAL)
- Clear decision or primary recommendation
- Detailed reasoning with specific metrics and thresholds
- Summary of current metrics
- Threat assessment
- Recommended actions (prioritized list)
- Any regulatory concerns
- Tools used in analysis

IMPORTANT RULES:
- NEVER simulate attacks unless explicitly asked
- ALWAYS check regulatory compliance thresholds
- Provide specific, actionable recommendations
- Consider both immediate and strategic actions
- Note when regulatory notifications would be required
- Format monetary values in millions USD (MM)"""

    # Create agent using langgraph
    agent_executor = create_react_agent(
        llm, 
        ALL_TOOLS,
        prompt=system_message
    )
    
    return agent_executor


def extract_json_from_response(response_text: str) -> Dict[str, Any]:
    """
    Extract structured information from agent response
    
    Args:
        response_text: Raw response text from agent
    
    Returns:
        Dictionary with extracted structured data
    """
    # Try to extract JSON if present
    json_match = re.search(r'\{[\s\S]*\}', response_text)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
    
    # Fallback: Parse key information from text
    result = {
        "risk_level": "UNKNOWN",
        "decision": "",
        "reasoning": "",
        "current_metrics_summary": {},
        "threat_assessment": "",
        "recommended_actions": [],
        "regulatory_concerns": [],
        "tools_used": []
    }
    
    # Extract risk level
    if "CRITICAL" in response_text.upper():
        result["risk_level"] = "CRITICAL"
    elif "AT_RISK" in response_text.upper() or "AT RISK" in response_text.upper():
        result["risk_level"] = "AT_RISK"
    elif "STABLE" in response_text.upper():
        result["risk_level"] = "STABLE"
    
    # Extract sections
    sections = response_text.split('\n')
    current_section = None
    
    for line in sections:
        line = line.strip()
        if not line:
            continue
            
        # Identify sections
        if "recommendation" in line.lower() or "decision" in line.lower():
            current_section = "decision"
        elif "reasoning" in line.lower() or "analysis" in line.lower():
            current_section = "reasoning"
        elif "threat" in line.lower():
            current_section = "threat"
        elif "action" in line.lower() and "recommend" in line.lower():
            current_section = "actions"
        elif "regulatory" in line.lower() or "compliance" in line.lower():
            current_section = "regulatory"
        elif current_section == "actions" and (line.startswith('-') or line.startswith('•') or line.startswith('*')):
            result["recommended_actions"].append(line.lstrip('-•* '))
        elif current_section == "regulatory" and (line.startswith('-') or line.startswith('•') or line.startswith('*')):
            result["regulatory_concerns"].append(line.lstrip('-•* '))
    
    # Set reasoning to full text if not extracted
    if not result["reasoning"]:
        result["reasoning"] = response_text
    
    return result


def display_assessment(assessment: Dict[str, Any], raw_response: str = None):
    """
    Display assessment results in a formatted, user-friendly way
    
    Args:
        assessment: Structured assessment data
        raw_response: Raw agent response for context
    """
    # Risk level emoji mapping
    risk_emoji = {
        "STABLE": "✅",
        "AT_RISK": "⚠️",
        "CRITICAL": "🚨"
    }
    
    print("\n" + "="*80)
    print("🛡️  FINANCIAL CYBER RESILIENCE ASSESSMENT")
    print("="*80)
    
    # Risk Level
    risk_level = assessment.get("risk_level", "UNKNOWN")
    emoji = risk_emoji.get(risk_level, "❓")
    print(f"\n{emoji} RISK LEVEL: {risk_level}")
    
    # Display raw response if available (this shows the agent's analysis)
    if raw_response:
        print("\n" + "-"*80)
        print("📊 ASSESSMENT DETAILS:")
        print("-"*80)
        print(raw_response)
    
    # Decision
    if assessment.get("decision"):
        print("\n" + "-"*80)
        print("💡 PRIMARY RECOMMENDATION:")
        print("-"*80)
        print(assessment["decision"])
    
    # Recommended Actions
    if assessment.get("recommended_actions"):
        print("\n" + "-"*80)
        print("📋 RECOMMENDED ACTIONS:")
        print("-"*80)
        for i, action in enumerate(assessment["recommended_actions"], 1):
            print(f"{i}. {action}")
    
    # Regulatory Concerns
    if assessment.get("regulatory_concerns"):
        print("\n" + "-"*80)
        print("⚖️  REGULATORY CONCERNS:")
        print("-"*80)
        for concern in assessment["regulatory_concerns"]:
            print(f"  ⚠️  {concern}")
    
    print("\n" + "="*80 + "\n")


def main():
    """
    Main interactive CLI for the Financial Cyber Resilience Agent
    """
    print("="*80)
    print("🛡️  Financial Cyber Resilience AI Agent")
    print("="*80)
    print("\nEdge-deployed AI agent for financial institution resilience assessment")
    print("Powered by Ollama (Mistral) + LangChain - No cloud API required")
    print("\n" + "="*80)
    
    # Create agent
    print("\n🔧 Initializing agent...")
    try:
        agent = create_resilience_agent(verbose=True)
        print("✅ Agent ready!\n")
    except Exception as e:
        print(f"❌ Failed to initialize agent: {e}")
        print("\nMake sure Ollama is running: ollama serve")
        print("And Mistral model is installed: ollama pull mistral")
        return
    
    # Example queries
    examples = [
        "What is the current resilience status of our financial institution?",
        "Assess our preparedness for a ransomware attack",
        "What would happen if we experienced a data breach?",
        "Are we in compliance with regulatory requirements?",
        "Simulate a DDoS attack and recommend recovery actions"
    ]
    
    print("💡 Example queries:")
    for i, example in enumerate(examples, 1):
        print(f"  {i}. {example}")
    
    print("\n" + "-"*80)
    print("Type your question or 'quit' to exit")
    print("-"*80 + "\n")
    
    # Interactive loop
    while True:
        try:
            user_input = input("🤔 Your question: ").strip()
            
            if not user_input:
                continue
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                print("\n👋 Thank you for using Financial Cyber Resilience Agent!")
                break
            
            print("\n🤖 Agent is analyzing...\n")
            
            # Execute agent with new API
            result = agent.invoke({"messages": [HumanMessage(content=user_input)]})
            
            # Extract output from messages
            output = ""
            if isinstance(result, dict) and "messages" in result:
                for msg in result["messages"]:
                    if hasattr(msg, 'content'):
                        output += msg.content + "\n"
            else:
                output = str(result)
            
            # Extract and display results
            assessment = extract_json_from_response(output)
            display_assessment(assessment, output)
            
        except KeyboardInterrupt:
            print("\n\n👋 Interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}\n")
            continue


if __name__ == "__main__":
    main()
