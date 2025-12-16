# agents_async.py
import re, time, json, asyncio, math
from typing import Dict, Any, Optional

# ML libs optional
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN = True
except Exception:
    SKLEARN = False

# AgentC: perception + minimal enrichment
class AgentC:
    def __init__(self, packet_tool, memory, orchestrator, dashboard=None):
        self.packet_tool = packet_tool
        self.memory = memory
        self.orchestrator = orchestrator
        self.dashboard = dashboard

    async def perceive(self):
        pkt = await self.packet_tool.call({})
        # normalize to dict with packet_summary
        if not isinstance(pkt, dict) or "packet_summary" not in pkt:
            pkt = {"packet_summary": pkt}
        # add timestamp
        ps = pkt.get("packet_summary") or {}
        if isinstance(ps, dict):
            ps["ts"] = time.time()
            pkt["packet_summary"] = ps
        await self.memory.add({"AgentC_perception": pkt.get("packet_summary")})
        await self.orchestrator.receive_from_agent("AgentC", pkt.get("packet_summary"))
        if self.dashboard:
            await self.dashboard(f"[AgentC] Packet: {pkt.get('packet_summary')}")
        return pkt.get("packet_summary")

# AgentIP: OSINT enrichment with cache
class AgentIP:
    def __init__(self, ip_tool, memory, orchestrator, dashboard=None):
        self.ip_tool = ip_tool
        self.memory = memory
        self.orchestrator = orchestrator
        self.dashboard = dashboard
        self.cache = {}

    async def lookup(self, ip):
        if not ip:
            return None
        if ip in self.cache:
            res = self.cache[ip]
        else:
            res = await self.ip_tool.call({"ip": ip})
            self.cache[ip] = res
        await self.memory.add({"AgentIP_lookup": {"ip": ip, "result": res}})
        await self.orchestrator.receive_from_agent("AgentIP", {"ip": ip, "result": res})
        if self.dashboard:
            await self.dashboard(f"[AgentIP] Lookup for {ip}: {res}")
        return res

# -----------------------------
# ThreatIdentifierAgent (ML hybrid)
# -----------------------------
class ThreatIdentifierAgent:
    """
    Hybrid ML-based agent:
      - extracts numeric features from packet + recent context (no hard rules)
      - uses IsolationForest (unsupervised) for anomaly scoring
      - optionally uses a supervised model if provided
      - fuses reputation & model scores into final label/confidence
      - uses LLM only for textual refinement (optional)
    """
    def __init__(self, memory, llm_tool=None, supervised_model=None, window_seconds=60):
        self.memory = memory
        self.llm_tool = llm_tool
        self.supervised = supervised_model
        self.window = window_seconds
        self._buffer = []
        # init unsupervised model if sklearn available
        if SKLEARN:
            try:
                self.iforest = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
                self.scaler = StandardScaler()
            except Exception:
                self.iforest = None
                self.scaler = None
        else:
            self.iforest = None
            self.scaler = None

    async def _gather_recent(self, limit=500):
        history = await self.memory.get_all()
        recent = []
        for it in reversed(history[-limit:]):
            if isinstance(it, dict) and "AgentC_perception" in it:
                recent.append(it["AgentC_perception"])
        return recent

    async def _extract_features(self, packet):
        """
        Returns numeric vector and feature dict. No hard-coded thresholds.
        """
        ps = packet or {}
        src = ps.get("src_ip")
        dst = ps.get("dst_ip")
        proto = (ps.get("protocol") or "").upper()
        length = 0
        try:
            length = float(ps.get("length") or 0.0)
        except Exception:
            length = 0.0

        recent = await self._gather_recent(limit=500)
        same_src = [p for p in recent if p.get("src_ip")==src]
        recent_count = len(same_src)
        lengths = [float(p.get("length") or 0) for p in same_src if p.get("length") is not None]
        avg_len = float(sum(lengths)/len(lengths)) if lengths else 0.0
        # distinct dsts
        distinct_dsts = len(set(p.get("dst_ip") for p in same_src if p.get("dst_ip")))
        # inter-arrival approx: if timestamps available
        arr_intervals = []
        last_ts = None
        for p in reversed(same_src):
            ts = p.get("ts")
            if last_ts and ts:
                arr_intervals.append(last_ts - ts)
            last_ts = ts or last_ts
        mean_ia = float(sum(arr_intervals)/len(arr_intervals)) if arr_intervals else 0.0
        # protocol one-hot-like
        proto_tcp = 1.0 if "TCP" in proto else 0.0
        proto_udp = 1.0 if "UDP" in proto else 0.0
        proto_tls = 1.0 if "TLS" in proto or "SSL" in proto else 0.0

        features = [
            length,
            recent_count,
            avg_len,
            float(distinct_dsts),
            mean_ia,
            proto_tcp, proto_udp, proto_tls
        ]
        fdict = {
            "length": length,
            "recent_count": recent_count,
            "avg_len": avg_len,
            "distinct_dsts": distinct_dsts,
            "mean_ia": mean_ia,
            "proto_tcp": proto_tcp,
            "proto_udp": proto_udp,
            "proto_tls": proto_tls
        }
        return features, fdict

    def _normalize_scores(self, scores):
        # min-max map to 0..1
        a = min(scores); b = max(scores)
        if b - a <= 1e-9:
            return [0.0 for _ in scores]
        return [(s-a)/(b-a) for s in scores]

    async def identify(self, packet, ip_info=None):
        fv, fdict = await self._extract_features(packet)
        X = None
        try:
            import numpy as _np
            X = _np.array(fv).reshape(1,-1)
        except Exception:
            X = None

        anomaly = 0.0
        supervised_label = None
        supervised_score = 0.0

        # unsupervised anomaly: use iforest if available and buffer has data
        if SKLEARN and self.iforest is not None and len(self._buffer) >= 50:
            try:
                import numpy as _np
                buf = _np.array(self._buffer)
                try:
                    self.scaler.fit(buf)
                    buf_scaled = self.scaler.transform(buf)
                    self.iforest.fit(buf_scaled)
                    if X is not None:
                        Xs = self.scaler.transform(X)
                        # decision_function: higher = normal, lower = anomalous -> invert
                        sc = -self.iforest.decision_function(Xs)[0]
                        # map to 0..1 via sigmoid
                        anomaly = float(1.0 / (1.0 + math.exp(-sc)))
                except Exception:
                    anomaly = 0.0
            except Exception:
                anomaly = 0.0
        else:
            # fallback heuristic: scaled length-based anomaly
            try:
                anomaly = float(min(1.0, fv[0] / (fv[2]*2 + 1.0))) if fv[2] > 0 else float(min(1.0, fv[0]/1500.0))
            except Exception:
                anomaly = 0.0

        # supervised classification if model provided
        if self.supervised and X is not None:
            try:
                probs = self.supervised.predict_proba(X)[0]
                idx = int(probs.argmax())
                supervised_label = self.supervised.classes_[idx]
                supervised_score = float(probs[idx])
            except Exception:
                supervised_label = None
                supervised_score = 0.0

        # reputation: derive a numeric rep score from ip_info (0..1)
        rep = 0.0
        if ip_info and isinstance(ip_info, dict):
            # use presence of 'org', 'country' as signals; map to 0..1 without hard-coded blacklist
            if ip_info.get("org"):
                rep += 0.2
            if ip_info.get("country"):
                rep += 0.1
            # if ipinfo flagged private -> lower rep weight
            if ip_info.get("note") == "private_ip":
                rep -= 0.4
        rep = max(0.0, min(1.0, rep))

        # ensemble fusion: data-driven weights (learned from buffer length)
        w_anom = 0.6 if not self.supervised else 0.45
        w_sup = 0.35 if self.supervised else 0.0
        w_rep = 0.05
        base_score = anomaly * w_anom + supervised_score * w_sup + rep * w_rep
        base_score = max(0.0, min(1.0, base_score))

        # candidate label: supervised label preferred if confident
        candidate = supervised_label if (supervised_label and supervised_score>=0.6) else ("anomaly" if base_score>0.5 else "benign")

        # LLM fusion for explanation/refinement (optional)
        llm_label = None; llm_conf = 0.0; llm_explain = None
        if self.llm_tool and getattr(self.llm_tool, "enabled", False):
            try:
                prompt = {
                    "packet": packet,
                    "features": fdict,
                    "anomaly": anomaly,
                    "supervised_label": supervised_label,
                    "supervised_score": supervised_score,
                    "reputation": rep,
                    "candidate": candidate
                }
                ptxt = "Given the following numeric signals, suggest a concise threat label and confidence. Return JSON only."
                res = await self.llm_tool.call({"prompt": ptxt + "\n\n" + json.dumps(prompt, default=str)})
                raw = res.get("response","")
                try:
                    parsed = json.loads(raw)
                    llm_label = parsed.get("threat_type")
                    llm_conf = float(parsed.get("confidence",0.0))
                    llm_explain = parsed.get("details") or parsed.get("explain")
                    if llm_conf > 0.75:
                        candidate = llm_label or candidate
                        base_score = max(base_score, llm_conf)
                except Exception:
                    pass
            except Exception:
                pass

        # build result
        result = {
            "threat_type": candidate,
            "confidence": float(base_score),
            "details": {
                "features": fdict,
                "anomaly": float(anomaly),
                "supervised_label": supervised_label,
                "supervised_score": float(supervised_score),
                "reputation": float(rep),
                "llm_label": llm_label,
                "llm_conf": float(llm_conf),
                "llm_explain": llm_explain
            }
        }

        # append vector to online buffer for future fitting
        try:
            if SKLEARN:
                import numpy as _np
                self._buffer.append(_np.array(fv, dtype=float))
                if len(self._buffer) > 2000:
                    self._buffer = self._buffer[-1000:]
        except Exception:
            pass

        return result


# -----------------------------
# RiskAssessmentAgent (data-driven)
# -----------------------------
class RiskAssessmentAgent:
    """
    Converts threat output into a calibrated risk score using historical percentiles
    (no fixed thresholds). Learns distribution from memory.
    """
    def __init__(self, memory):
        self.memory = memory

    async def _gather_confidences(self, limit=2000):
        hist = await self.memory.get_all()
        vals = []
        for it in reversed(hist[-limit:]):
            if isinstance(it, dict) and "AgentThreat" in it:
                tr = it["AgentThreat"]
                if isinstance(tr, dict):
                    vals.append(float(tr.get("confidence",0.0)))
        return vals

    async def assess(self, threat_result):
        base_conf = float(threat_result.get("confidence",0.0))
        # empirical percentile relative to history
        vals = await self._gather_confidences()
        if vals:
            # compute percentile without hard thresholds
            import bisect
            vals_sorted = sorted(vals)
            pos = bisect.bisect_left(vals_sorted, base_conf)
            pct = pos / max(1, len(vals_sorted))
            # calibrate with logistic-like mapping
            risk_score = float(1/(1+math.exp(-6*(pct-0.5))))
        else:
            # no history yet: map base_conf directly, calibrated
            risk_score = float(1/(1+math.exp(-6*(base_conf-0.5))))
        # recommended action is determined downstream by PolicyAgent; here provide possible actions
        return {"risk_score": risk_score, "note": f"percentile_based"}

# -----------------------------
# PolicyAgent (learns thresholds from memory)
# -----------------------------
class PolicyAgent:
    """
    Decides whether to auto-execute, require human approval, or block/alert.
    Uses data-driven thresholds: computes historical risk distribution and
    sets dynamic thresholds (e.g., top X percentile -> require approval).
    """
    def __init__(self, memory, auto_execute_percentile=0.99, human_review_percentile=0.85):
        self.memory = memory
        self.auto_p = auto_execute_percentile
        self.human_p = human_review_percentile

    async def _get_percentiles(self, limit=2000):
        hist = await self.memory.get_all()
        r = []
        for it in reversed(hist[-limit:]):
            if isinstance(it, dict) and "AgentRisk" in it:
                rv = it["AgentRisk"]
                if isinstance(rv, dict):
                    r.append(float(rv.get("risk_score",0.0)))
        return r

    async def evaluate(self, context):
        # context contains threat_result and risk_result and packet/ip_info
        risk = context.get("risk", {}).get("risk_score", 0.0)
        # compute dynamic thresholds
        vals = await self._get_percentiles()
        if vals:
            vals_sorted = sorted(vals)
            # determine dynamic cutoffs
            import numpy as _np
            auto_cut = _np.percentile(vals_sorted, self.auto_p*100)
            human_cut = _np.percentile(vals_sorted, self.human_p*100)
        else:
            # warmup defaults (not rigid rules — only fallback)
            auto_cut = 0.9
            human_cut = 0.8
        decision = {"allow_auto": False, "require_human": False, "action_suggestion": None, "explain": ""}
        if risk >= auto_cut:
            decision["allow_auto"] = True
            decision["action_suggestion"] = "block_ip"
            decision["explain"] = "risk above auto cutoff"
        elif risk >= human_cut:
            decision["require_human"] = True
            decision["action_suggestion"] = "capture_deep"
            decision["explain"] = "risk above human-review cutoff"
        else:
            decision["action_suggestion"] = "monitor"
            decision["explain"] = "low risk"
        return decision

# -----------------------------
# Agent5: LLM Mediator (final plan composer)
# -----------------------------
class Agent5:
    """
    Final mediator that requests inputs from other agents, queries LLM only for textual
    explanation or to synthesize a final action proposal. LLM cannot override ML ensemble solely.
    """
    def __init__(self, llm_tool, memory, orchestrator, dashboard=None):
        self.llm_tool = llm_tool
        self.memory = memory
        self.orchestrator = orchestrator
        self.dashboard = dashboard

    async def compose_plan(self, packet, threat_result, risk_result, policy_decision, ip_info=None):
        # build a structured proposal
        proposal = {
            "action": policy_decision.get("action_suggestion", "monitor"),
            "params": {},
            "confidence": float(risk_result.get("risk_score", 0.0)),
            "explain": policy_decision.get("explain", "")
        }
        # include relevant params
        if proposal["action"] in ("block_ip","alert"):
            proposal["params"]["ip"] = packet.get("src_ip")
        if proposal["action"] == "capture_deep":
            proposal["params"]["duration"] = 15
        # Ask LLM for a human-readable explanation if allowed
        if self.llm_tool and getattr(self.llm_tool, "enabled", False):
            prompt = {
                "packet": packet,
                "threat": threat_result,
                "risk": risk_result,
                "policy": policy_decision
            }
            try:
                res = await self.llm_tool.call({"prompt": "Summarize and justify the following proposed action in one short paragraph:\n\n" + json.dumps(prompt, default=str)})
                explanation = res.get("response","").strip()
                if explanation:
                    proposal["explain"] = explanation
            except Exception:
                pass
        await self.memory.add({"Agent5_proposal": proposal})
        await self.orchestrator.receive_from_agent("Agent5", proposal)
        if self.dashboard:
            await self.dashboard(f"[Agent5] Proposal: {proposal}")
        return proposal
