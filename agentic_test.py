import os
import json
import subprocess
from openai import OpenAI

client = OpenAI()

def run_ares_module(module_name, target, objective):
    print(f"[Agent] Calling ARES module: {module_name} on {target}")
    cmd = [
        "node", "--experimental-strip-types",
        "/home/ubuntu/OurMine/bin/ourmine.ts",
        "pentest", target,
        "--live",
        "--objective", objective,
        "--module", module_name
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def agentic_mission(objective, target):
    print(f"--- [AGENTIC MISSION START] ---")
    print(f"Objective: {objective}")
    print(f"Target: {target}")
    
    # 1. Ask the model to pick the departments
    prompt = f"""
    You are the ARES Syndicate Prime Commander. 
    Mission Objective: {objective}
    Target: {target}
    
    Available ARES Departments:
    - ares_shadow_organization (Orchestrator)
    - ares_innovation_engine (Research)
    - ares_specialized_impact (OT/SCADA)
    - ares_financial_warfare (DeFi/Crypto)
    - ares_raas_advanced (Ransomware)
    - ares_anti_forensics (Stealth)
    
    Pick the 3 most critical departments for this mission and explain why.
    Output JSON format: {{"departments": ["dept1", "dept2", "dept3"], "reasoning": "..."}}
    """
    
    response = client.chat.completions.create(
        model="gpt-5-mini",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"}
    )
    print(f"DEBUG: Response: {response}")
    if not response.choices:
        print("ERROR: No choices returned from LLM")
        return
    
    plan = json.loads(response.choices[0].message.content)
    print(f"\n[AI Plan]: {plan['reasoning']}")
    
    # 2. Execute each department
    for dept in plan['departments']:
        output = run_ares_module(dept, target, objective)
        print(f"\n--- [{dept} Output] ---")
        # Summarize output for the agent
        summary_prompt = f"Summarize the critical findings from this tool output in 2 sentences:\n{output}"
        summary_resp = client.chat.completions.create(
            model="gpt-5-mini",
            messages=[{"role": "user", "content": summary_prompt}]
        )
        print(summary_resp.choices[0].message.content)

    print(f"\n--- [AGENTIC MISSION COMPLETE] ---")

if __name__ == "__main__":
    agentic_mission(
        "Infiltrate the bank at 127.0.0.1:8888, exfiltrate vault data, and deploy ransomware.",
        "127.0.0.1"
    )
