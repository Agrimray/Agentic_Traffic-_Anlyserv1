# main_async.py
'''import asyncio
import os
from tools_async import PacketCaptureTool, LLMTool, IPInfoTool, BlockIPTool, AlertTool, CaptureDeepTool, ActionTool
from memory_async import Memory
from agents_async import AgentC, AgentIP, ThreatIdentifierAgent, RiskAssessmentAgent, PolicyAgent, Agent5
from orchestrator_async import Orchestrator
from cli_dashboard import dashboard_print

async def main():
    # config
    dry_run = os.environ.get("DRY_RUN","1") == "1"
    enable_llm = os.environ.get("ENABLE_LLM","0") == "1"

    # tools
    packet_tool = PacketCaptureTool()
    llm_tool = LLMTool(enabled=enable_llm)
    ip_tool = IPInfoTool(token=os.environ.get("IPINFO_TOKEN"))

    # action tools
    action_tools = {
        "block_ip": BlockIPTool(dry_run=dry_run),
        "alert": AlertTool(dry_run=dry_run),
        "capture_deep": CaptureDeepTool(dry_run=dry_run),
        "monitor": ActionTool(dry_run=True)
    }

    # core infra
    memory = Memory()
    orchestrator = Orchestrator(action_tools=action_tools)

    # agents
    agentC = AgentC(packet_tool, memory, orchestrator, dashboard=dashboard_print)
    agentIP = AgentIP(ip_tool, memory, orchestrator, dashboard=dashboard_print)
    threat_agent = ThreatIdentifierAgent(memory, llm_tool=llm_tool, supervised_model=None)
    risk_agent = RiskAssessmentAgent(memory)
    policy_agent = PolicyAgent(memory)
    agent5 = Agent5(llm_tool, memory, orchestrator, dashboard=dashboard_print)

    try:
        await orchestrator.run(agentC, agentIP, threat_agent, risk_agent, policy_agent, agent5, delay=2)
    except KeyboardInterrupt:
        print("Shutting down...")

if __name__ == "__main__":
    asyncio.run(main())'''

# main_async.py
import asyncio
import os
import json

from tools_async import (
    PacketCaptureTool, LLMTool, IPInfoTool,
    BlockIPTool, AlertTool, CaptureDeepTool, ActionTool
)
from memory_async import Memory
from agents_async import (
    AgentC, AgentIP, ThreatIdentifierAgent,
    RiskAssessmentAgent, PolicyAgent, Agent5
)
from orchestrator_async import Orchestrator
from cli_dashboard import dashboard_print


# -----------------------------------------------------------
# FIX: Human approval loop added so block_ip simulation runs
# -----------------------------------------------------------
async def human_approval_loop(orchestrator):
    while True:
        proposal = await orchestrator.request_human_approval()
        print("\n⚠ HUMAN APPROVAL REQUIRED ⚠")
        print(json.dumps(proposal, indent=2))

        choice = input("Approve? (y/n): ").strip().lower()
        if choice == "y":
            tool = orchestrator.action_tools[proposal["action"]]
            result = await tool.call(proposal["params"])
            print(">>> BLOCK-IP EXECUTED:", result)
        else:
            print(">>> BLOCK REJECTED")


# -----------------------------------------------------------
# Main
# -----------------------------------------------------------
async def main():
    # config
    dry_run = os.environ.get("DRY_RUN", "1") == "1"
    enable_llm = os.environ.get("ENABLE_LLM", "0") == "1"

    # tools
    packet_tool = PacketCaptureTool()
    llm_tool = LLMTool(enabled=enable_llm)
    ip_tool = IPInfoTool(token=os.environ.get("IPINFO_TOKEN"))

    # action tools
    action_tools = {
        "block_ip": BlockIPTool(dry_run=dry_run),
        "alert": AlertTool(dry_run=dry_run),
        "capture_deep": CaptureDeepTool(dry_run=dry_run),
        "monitor": ActionTool(dry_run=True)
    }

    # core infra
    memory = Memory()
    orchestrator = Orchestrator(action_tools=action_tools)

    # agents
    agentC = AgentC(packet_tool, memory, orchestrator, dashboard=dashboard_print)
    agentIP = AgentIP(ip_tool, memory, orchestrator, dashboard=dashboard_print)
    threat_agent = ThreatIdentifierAgent(memory, llm_tool=llm_tool, supervised_model=None)
    risk_agent = RiskAssessmentAgent(memory)
    policy_agent = PolicyAgent(memory)
    agent5 = Agent5(llm_tool, memory, orchestrator, dashboard=dashboard_print)

    try:
        # -----------------------------------------------------------
        # FIX: Start human approval loop
        # -----------------------------------------------------------
        approval_task = asyncio.create_task(human_approval_loop(orchestrator))

        # Run orchestrator loop
        await orchestrator.run(
            agentC, agentIP, threat_agent, risk_agent,
            policy_agent, agent5, delay=2
        )

    except KeyboardInterrupt:
        print("Shutting down...")


if __name__ == "__main__":
    asyncio.run(main())
