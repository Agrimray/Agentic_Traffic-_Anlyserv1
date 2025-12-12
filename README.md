## 🔒 **Overview**

This project implements a fully autonomous **Agentic AI–based Security Operations Center (SOC)** built **without using any pre-existing agentic AI frameworks or toolkits**.
All agentic behavior—perception, reasoning, memory, planning, and action execution—is implemented manually using Python's asynchronous architecture.

The system continuously:

* Captures live packets
* Enriches them with OSINT data
* Performs rule-based threat analysis
* Computes risk
* Applies security policies
* Generates autonomous action plans
* Executes allowed actions
* Sends others for human approval

It operates as a **multi-agent autonomous system** built from scratch.

---

# 🤖 **Agentic AI Architecture**

## **What Makes This System Agentic?**

Agentic AI refers to systems where multiple autonomous agents perceive, reason, and act toward shared goals.

This project implements agentic principles **without any external SDK** (no Google ADK, no LangChain agents, no AutoGen, no CrewAI, no OpenAI agents).
Everything is **custom-built in Python**.

### ✔ **Autonomy**

Each agent runs asynchronously, makes independent decisions, and contributes to the final action.

### ✔ **Perception → Reasoning → Action Pipeline**

Every cycle:

1. The system **perceives** network traffic (AgentC)
2. **Understands** it using OSINT + threat logic (AgentIP, Threat Agent)
3. **Evaluates risk** (Risk Agent)
4. **Applies policy** (Policy Agent)
5. **Plans actions** (Agent5)
6. **Executes** via Orchestrator

This mimics human SOC analysts but in an automated, agent-driven way.

### ✔ **Multi-Agent Collaboration (Decentralized Intelligence)**

Each agent specializes in a unique task:

| Agent                     | Responsibility                        |
| ------------------------- | ------------------------------------- |
| **AgentC**                | Perception (packet capture)           |
| **AgentIP**               | OSINT enrichment                      |
| **ThreatIdentifierAgent** | Behavior analysis (rule-based)        |
| **RiskAssessmentAgent**   | Numerical risk scoring                |
| **PolicyAgent**           | Rule-based action selection           |
| **Agent5**                | Executive reasoning + action proposal |
| **Orchestrator**          | Governance + tool execution           |

No agent directly controls others—they communicate through a central orchestrator.

### ✔ **Shared Memory for Context**

The `memory_async.py` module:

* Stores past observations
* Allows agents to detect unusual frequency
* Enables context-aware reasoning
* Helps replicate long-term analytical behavior

### ✔ **Governance & Human-in-the-loop Safety**

The orchestrator enforces:

* Human approval for dangerous actions
* Audit logging
* Structured agent workflows

### ✔ **No Pre-trained Models**

This Agentic SOC:

* Does *not* use machine learning
* Does *not* rely on pretrained anomaly detection
* Runs purely on structured reasoning and rule-based scoring

This makes the system deterministic, explainable, and suitable for compliance-heavy environments.

---

# 📁 **Project Structure**

```
agentic_soc/
│
├── main_async.py             # Application entrypoint
├── orchestrator_async.py     # Agent coordination + action execution layer
├── agents_async.py           # All agents (perception, analysis, risk, policy, decision)
├── tools_async.py            # Tshark capture, IPInfo lookup, deep capture, monitoring tools
├── memory_async.py           # Shared memory system for agent reasoning
├── cli_dashboard.py          # Real-time dashboard logging
├── traffic_gen.py            # Benign traffic generator for testing
└── orchestrator_audit.log    # Auto-generated audit log
```

---

# ⚙️ **System Requirements**

### **Operating System**

* Windows 10/11
* Linux (Ubuntu recommended)
* macOS (requires Tshark support)

### **Python**

* Python **3.9 or higher**

### **Network Requirements**

* Administrator/root permissions for packet capture
* Tshark installed

---

# 📦 **Python Dependencies**

Install all required Python libraries:

```
pip install scapy pyshark ipinfo requests
```

If on Windows and pyshark complains:

```
pip install lxml
```

---

# 🧰 **Install Tshark**

## Windows

1. Download Wireshark → [https://www.wireshark.org/download.html](https://www.wireshark.org/download.html)
2. Ensure **Npcap** is installed
3. Ensure Tshark is added to PATH

Test:

```
tshark -v
```

## Linux

```
sudo apt update
sudo apt install tshark
sudo usermod -aG wireshark $USER
```

Log out & log in again.

## macOS

```
brew install wireshark
```

Allow packet capture in System Settings.

---

# 🌍 **Environment Variables (Optional)**

### Windows (PowerShell)

```
setx DRY_RUN "1"
setx ENABLE_LLM "0"
setx IPINFO_TOKEN "your_token_here"
```

### Meaning:

* **DRY_RUN=1** → IP blocking and firewall actions will NOT be executed
* **ENABLE_LLM=0** → disables LLM reasoning (default)
* **IPINFO_TOKEN** → enables full IP reputation data

---

# ▶️ **How to Run the System**

### **Step 1 — Navigate to folder**

```
cd agentic_soc
```

### **Step 2 — Install dependencies**

```
pip install -r requirements.txt
```

(I can generate requirements.txt for you if needed.)

### **Step 3 — Verify Tshark**

```
tshark -D
```

You should see a numbered list of interfaces.

### **Step 4 — Run the SOC**

```
python main_async.py
```

What happens:

* System asks/selects capture interface
* Agents begin analyzing packets
* Dashboard prints decisions
* Orchestrator logs everything

### **Step 5 — Check audit logs**

```
cat orchestrator_audit.log
```

---

# 🧪 **Testing With Synthetic Traffic**

To generate benign multicast noise:

```
python traffic_gen.py
```

Useful for testing:

* packet perception
* threat & risk scoring
* agent workflow

---

# 🧩 **Understanding Each Agent (Detailed Agentic Roles)**

### **1. AgentC (Perception Agent)**

* Captures packets
* Normalizes fields
* Sends raw data to memory and orchestrator

### **2. AgentIP (OSINT Intelligence Agent)**

* Queries IPInfo API
* Adds intelligence metadata
* Logs results for correlation

### **3. ThreatIdentifierAgent (Analysis Agent)**

* Checks packet behavior
* Looks at:

  * frequency
  * size patterns
  * destination variety
  * timing differences
* Produces threat label

### **4. RiskAssessmentAgent (Evaluation Agent)**

* Converts threat signals into a numeric risk score

### **5. PolicyAgent (Rule Governance Agent)**

* Decides:

  * monitor
  * capture deeper
  * block
  * alert

### **6. Agent5 (Executive Agent)**

* Combines all outputs
* Generates final recommended action
* Provides confidence + reasoning

### **7. Orchestrator (Manager Agent)**

* Executes approved actions
* Queues dangerous ones for human approval
* Logs all events
* Maintains agent independence

---

# 🛡️ **Why This System Is Truly Agentic AI**

This project demonstrates agentic architecture by:

### ✔ Independent, specialized agents

### ✔ Shared memory for context

### ✔ Autonomous perception and action

### ✔ Planning and decision fusion

### ✔ Human-in-the-loop safety

### ✔ Asynchronous execution

### ✔ No reliance on external agentic frameworks

It represents a **manually engineered agentic SOC**, ideal for research, teaching, cybersecurity prototyping, and demonstrating autonomous AI principles.


