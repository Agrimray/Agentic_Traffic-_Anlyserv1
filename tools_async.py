# tools_async.py

import os
import json
import asyncio
import subprocess
import shlex
import ipaddress
import time

# Optional pyshark for packet capture
try:
    import pyshark
except Exception:
    pyshark = None

# Basic MCPTool interface
class MCPTool:
    async def call(self, inputs):
        raise NotImplementedError()

# -----------------------------
# Packet capture tool (robust)
# -----------------------------
class PacketCaptureTool(MCPTool):
    def __init__(self, default_iface=None):
        self.interface = default_iface

    def _list_tshark_interfaces(self):
        try:
            raw = subprocess.check_output(["tshark", "-D"], stderr=subprocess.STDOUT, text=True)
        except Exception:
            raise RuntimeError("TShark not installed or not found in PATH")

        interfaces = []
        for line in raw.splitlines():
            line = line.strip()
            if ". " not in line:
                continue

            idx_str, rest = line.split(". ", 1)
            try:
                idx = int(idx_str)
            except:
                continue

            device_token = rest.split(" ")[0].strip()
            interfaces.append((idx, device_token, rest))

        return interfaces

    async def select_interface(self):
        interfaces = self._list_tshark_interfaces()
        print("Available network interfaces:")
        for idx, token, full in interfaces:
            print(f"{idx}: {full}")

        while True:
            try:
                choice = int(input("Select interface number to capture packets from: ").strip())
                iface = [x for x in interfaces if x[0] == choice][0]
                self.interface = iface[1]   # device token
                print(f"Selected interface: {self.interface}")
                break
            except:
                print("Invalid choice, try again.")

    def _capture_once(self):
        if not self.interface:
            return {"packet_summary": {"error": "no_interface_selected", "ts": time.time()}}

        cmd = [
            "tshark",
            "-l",
            "-i", self.interface,
            "-c", "1",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len"
        ]

        try:
            raw = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        except Exception as e:
            return {"packet_summary": {"error": str(e), "ts": time.time()}}

        lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]

        # 1️⃣ Remove tshark banner noise
        cleaned = []
        for ln in lines:
            if ln.startswith("Capturing on") or "packet captured" in ln:
                continue
            cleaned.append(ln)

        if not cleaned:
            return {"packet_summary": {"error": "no_packet_data", "ts": time.time()}}

        # 2️⃣ Prefer tab-separated fields
        for ln in cleaned:
            if "\t" in ln:
                fields = ln.split("\t")
                src = fields[0] if len(fields) > 0 else None
                dst = fields[1] if len(fields) > 1 else None
                proto = fields[2] if len(fields) > 2 else None
                length = fields[3] if len(fields) > 3 else None

                return {
                    "packet_summary": {
                        "src_ip": src,
                        "dst_ip": dst,
                        "protocol": proto,
                        "length": length,
                        "ts": time.time()
                    }
                }

        # 3️⃣ No tabs → extract IPv4/IPv6 manually
        import re
        text = " ".join(cleaned)
        ipv4 = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
        ipv6 = re.findall(r"[0-9A-Fa-f:]+:[0-9A-Fa-f:]+", text)

        src = ipv4[0] if ipv4 else (ipv6[0] if ipv6 else None)

        return {
            "packet_summary": {
                "src_ip": src,
                "dst_ip": None,
                "protocol": None,
                "length": None,
                "ts": time.time()
            }
        }

    async def call(self, inputs):
        if isinstance(inputs, dict) and inputs.get("iface"):
            self.interface = str(inputs.get("iface")).split()[0]

        if not self.interface:
            await self.select_interface()

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, self._capture_once)
        return result




# -----------------------------
# LLM tool — reads token from env and calls HF router
# -----------------------------
class LLMTool(MCPTool):
    def __init__(self, enabled=False):
        # enabled only if explicitly requested AND HF token is present
        hf_token = os.environ.get("HF_API_TOKEN")
        self.enabled = bool(enabled and hf_token)
        self.hf_token = hf_token
        self.api_url = os.environ.get("HF_API_URL", "https://router.huggingface.co/v1/chat/completions")
        self.model = os.environ.get("HF_MODEL", "meta-llama/Llama-3.1-8B-Instruct")
        self.headers = {"Content-Type": "application/json"}
        if self.hf_token:
            self.headers["Authorization"] = f"Bearer {self.hf_token}"

    async def call(self, inputs):
        """
        inputs: {"prompt": "..."}
        Returns: {"response": "..."} where response is string
        """
        if not self.enabled:
            # deterministic fallback response
            return {"response": json.dumps({"note":"LLM disabled or HF_API_TOKEN missing"})}
        prompt = inputs.get("prompt", "")
        payload = {"model": self.model, "messages": [{"role": "user", "content": prompt}]}
        loop = asyncio.get_event_loop()
        try:
            import requests
            resp = await loop.run_in_executor(None, lambda: requests.post(self.api_url, headers=self.headers, json=payload, timeout=30))
            data = resp.json()
            # robustly extract assistant content
            if isinstance(data, dict) and "choices" in data and len(data["choices"])>0:
                content = data["choices"][0].get("message", {}).get("content", "")
                return {"response": content}
            return {"response": json.dumps(data)}
        except Exception as e:
            return {"response": f"LLM error: {str(e)}"}


# -----------------------------
# IPInfo tool
# -----------------------------
class IPInfoTool(MCPTool):
    def __init__(self, token=None):
        self.token = token or os.environ.get("IPINFO_TOKEN")

    async def call(self, inputs):
        ip = inputs.get("ip") if isinstance(inputs, dict) else None
        if not ip:
            return {"error": "no_ip"}
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                return {"note": "private_ip", "ip": ip}
        except Exception:
            # could be invalid ip string; still try hitting API
            pass
        token = "251845cb14d90e"
        url = f"https://ipinfo.io/{ip}/json"
        headers = {"Authorization": f"Bearer {token}"} if self.token else {}
        loop = asyncio.get_event_loop()
        try:
            import requests
            resp = await loop.run_in_executor(None, lambda: requests.get(url, headers=headers, timeout=8))
        except Exception as e:
            return {"error": str(e)}
        try:
            if resp.status_code == 200:
                return resp.json()
            else:
                return {"error": f"ipinfo_{resp.status_code}", "text": resp.text}
        except Exception:
            return {"error": "invalid_json_response"}


# -----------------------------
# Action tools (dry-run safe by default)
# -----------------------------
class ActionTool(MCPTool):
    def __init__(self, dry_run=True):
        self.dry_run = bool(dry_run or os.environ.get("DRY_RUN", "1") == "1")

    async def call(self, inputs):
        return await self.run(inputs)

    async def run(self, inputs):
        raise NotImplementedError()


class BlockIPTool(ActionTool):
    async def run(self, inputs):
        ip = inputs.get("ip")
        if not ip:
            return {"error": "no_ip"}
        # build a system command for Linux example; Windows would require different commands (e.g., netsh)
        cmd = f"iptables -A INPUT -s {ip} -j DROP"
        if self.dry_run:
            return {"simulated": cmd}
        try:
            subprocess.check_output(shlex.split(cmd), stderr=subprocess.STDOUT)
            return {"ok": True, "cmd": cmd}
        except Exception as e:
            return {"error": str(e)}


class AlertTool(ActionTool):
    async def run(self, inputs):
        message = inputs.get("message", "alert")
        if self.dry_run:
            # simulate an alert
            return {"simulated": f"ALERT: {message}"}
        # production: you might send to webhook, email, syslog
        try:
            print("[ALERT]", message)
            return {"ok": True}
        except Exception as e:
            return {"error": str(e)}


class CaptureDeepTool(ActionTool):
    async def run(self, inputs):
        duration = int(inputs.get("duration", 10))
        out = inputs.get("out", "capture.pcap")
        iface = inputs.get("iface") or self.dry_run and "any" or ""
        # craft a cross-platform safe command only if not dry_run
        cmd = f"timeout {duration} tshark -i {iface} -w {out}"
        if self.dry_run:
            return {"simulated": cmd}
        try:
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            return {"ok": True, "file": out}
        except Exception as e:
            return {"error": str(e)}






