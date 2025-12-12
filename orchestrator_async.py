# orchestrator_async.py
import asyncio
import json
import time

class Orchestrator:
    def __init__(self, action_tools=None, audit_log_path="orchestrator_audit.log"):
        self.lock = asyncio.Lock()
        self.memory = []
        self.agent_data = {}
        self.task_queue = asyncio.Queue()
        self.action_tools = action_tools or {}
        self.audit_log_path = audit_log_path
        self.human_approval_queue = asyncio.Queue()

    async def _append_audit(self, entry):
        try:
            with open(self.audit_log_path, "a") as f:
                f.write(json.dumps({"ts": time.time(), **entry}) + "\n")
        except Exception:
            pass

    async def receive_from_agent(self, agent_name, data):
        async with self.lock:
            self.agent_data[agent_name] = data
            self.memory.append({agent_name: data})
        await self._append_audit({"from": agent_name, "data": data})
        # If Agent5 submits a proposal, push to task queue
        if agent_name == "Agent5" and isinstance(data, dict) and "action" in data:
            await self.task_queue.put(data)

    async def run(self, agentC, agentIP, threatAgent, riskAgent, policyAgent, agent5, delay=2):
        # start executor
        executor_task = asyncio.create_task(self._task_executor_loop())
        try:
            while True:
                pkt = await agentC.perceive()
                # enrich IP info asynchronously
                src = pkt.get("src_ip")
                ip_info = await agentIP.lookup(src) if src else None

                # Threat identification
                threat = await threatAgent.identify(pkt, ip_info=ip_info)
                await self.receive_from_agent("AgentThreat", threat)

                # Risk assessment
                risk = await riskAgent.assess(threat)
                await self.receive_from_agent("AgentRisk", risk)

                # Policy evaluation
                policy_decision = await policyAgent.evaluate({"threat":threat, "risk":risk, "packet":pkt, "ip_info": ip_info})
                await self.receive_from_agent("AgentPolicy", policy_decision)

                # Compose final proposal (Agent5)
                proposal = await agent5.compose_plan(pkt, threat, risk, policy_decision, ip_info=ip_info)
                # loop delay
                await asyncio.sleep(delay)
        except asyncio.CancelledError:
            executor_task.cancel()
            return

    # executor loop: handles proposals in background (applies action tools or queue for human)
    async def _task_executor_loop(self):
        while True:
            proposal = await self.task_queue.get()
            try:
                action = proposal.get("action")
                params = proposal.get("params", {})
                confidence = float(proposal.get("confidence", 0.0))
                # validate allowed actions
                if action not in self.action_tools:
                    await self._append_audit({"rejected":"action_not_allowed", "proposal":proposal})
                    continue
                tool = self.action_tools.get(action)
                # Policy: if tool requires human approval, enqueue for manual review
                # Here we decide by checking whether action is 'block_ip' and confidence low - but better: orchestrator can consult memory/policy.
                # We'll use a conservative default: require human if confidence < 0.75 for high-impact actions
                high_impact = (action == "block_ip")
                if high_impact and confidence < 0.75:
                    await self.human_approval_queue.put(proposal)
                    await self._append_audit({"queued_for_human": proposal})
                    continue
                # otherwise execute via tool (dry-run enforced in tools)
                res = await tool.call(params)
                await self._append_audit({"executed": action, "params": params, "result": res})
            except Exception as e:
                await self._append_audit({"executor_error": str(e), "proposal": proposal})

    # simple human approval API (blocking)
    async def request_human_approval(self):
        # returns next item that requires approval
        return await self.human_approval_queue.get()
