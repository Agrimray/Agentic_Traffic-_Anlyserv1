# memory_async.py
import asyncio
import json
import time
from typing import List, Dict, Any, Optional

class Memory:
    """
    Asynchronous shared memory for multi-agent systems.

    Features:
      - async-safe append using lock
      - optional memory limit (rolling window)
      - get_all() and get_recent()
      - summarize() for Level 4 (long-term reasoning)
    """

    def __init__(self, limit: Optional[int] = None):
        """
        limit: maximum number of entries to store (None = unlimited)
        """
        self.history: List[Dict[str, Any]] = []
        self.limit = limit
        self.lock = asyncio.Lock()

    async def add(self, item: Dict[str, Any]):
        """
        Add one memory record safely.
        """
        async with self.lock:
            self.history.append(item)

            # enforce limit (drop oldest entries)
            if self.limit and len(self.history) > self.limit:
                overflow = len(self.history) - self.limit
                self.history = self.history[overflow:]

    async def get_all(self) -> List[Dict[str, Any]]:
        """
        Return full memory copy.
        """
        async with self.lock:
            return list(self.history)

    async def get_recent(self, n: int = 50) -> List[Dict[str, Any]]:
        """
        Return last n memory entries.
        """
        async with self.lock:
            return self.history[-n:]

    async def summarize(self, last_n: int = 200) -> Dict[str, Any]:
        """
        Level-4: summarize recent memory for long-term agents.
        Produces structured summary suitable for LLM or RiskAnalysis.
        """

        async with self.lock:
            recent = self.history[-last_n:]

        summary = {
            "total_events": len(recent),
            "first_timestamp": None,
            "last_timestamp": None,
            "agent_counts": {},
            "ip_frequency": {},
            "protocol_frequency": {},
            "anomaly_mentions": 0,
        }

        for entry in recent:
            if not isinstance(entry, dict):
                continue

            # Determine agent source
            agent_name = next(iter(entry.keys()), None)
            summary["agent_counts"][agent_name] = summary["agent_counts"].get(agent_name, 0) + 1

            data = entry.get(agent_name)

            # Extract timestamps if present
            if isinstance(data, dict) and "ts" in data:
                ts = data.get("ts")
                if summary["first_timestamp"] is None:
                    summary["first_timestamp"] = ts
                summary["last_timestamp"] = ts

            # Extract IP & protocol frequencies from packet summaries
            if isinstance(data, dict):
                ps = data.get("packet_summary", data)
                if isinstance(ps, dict):
                    src = ps.get("src_ip")
                    proto = ps.get("protocol")
                    if src:
                        summary["ip_frequency"][src] = summary["ip_frequency"].get(src, 0) + 1
                    if proto:
                        summary["protocol_frequency"][proto] = summary["protocol_frequency"].get(proto, 0) + 1

            # Count anomaly mentions for detection patterns
            if isinstance(data, dict) and "anomaly" in json.dumps(data):
                summary["anomaly_mentions"] += 1

        return summary
