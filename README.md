# PRODUCTION ATTACK NARRATIVE PIPELINE  
## Detection Engineering Operating Model (Sensors → Correlation → Scoring)

**Author:** Ala Dabat  
**Discipline:** Detection Engineering / Threat Hunting  
**Philosophy:** First Principles → Minimum Truth → Reinforcement → Narrative Correlation  
**Scope:** Microsoft Sentinel / MDE (portable to other SIEM/XDR platforms)  
**Audience:** Detection Engineers, Senior SOC Analysts, Threat Hunters  

---

# 1. CORE PRINCIPLE

All production detection must begin from **Minimum Truth**:

> The single event that must occur for a specific attack behavior to exist.

Everything else is reinforcement, scoring, or narrative stitching.

We explicitly separate:

- Primitive vs Composite  
- Alert vs Incident  
- Sensor vs Narrative  
- Substrate vs Story  

This prevents ghost chains, brittle joins, and speculative attack narratives.

---

# 2. THREE-LAYER PRODUCTION MODEL

---

# LAYER 1 — SENSORS (ATOMIC TRUTHS)

Sensors are **always-on detections**, each anchored to a single minimum truth for a specific stage or surface.

They do NOT attempt to build the entire attack chain.

Each sensor represents one clear truth surface.

## 2.1 Sensor Categories (Endpoint-Centric Example)

### Execution
- Suspicious script host execution (PowerShell, wscript, mshta)
- LOLBin invoked with high-risk primitive

### Ingress / Tool Transfer
- Suspicious download
- File write to user-writable path with executable intent

### Persistence
Each is separate truth surface:
- Run key write
- TaskCache modification
- Service ImagePath write

### Privilege Escalation
- Token manipulation
- UAC bypass truth
- Suspicious privileged handle access (if signal exists)

### Lateral Movement
Separate cousins:
- Remote service execution
- WMI remote execution
- WinRM execution

### Command & Control
- Outbound connection from abnormal process
- Suspicious protocol or rare infrastructure pattern

---

## 2.2 Sensor Output Requirements

Each sensor must output:

- `DeviceId`
- `Account`
- `Process`
- `SHA256`
- `RemoteIP` / `RemoteDomain` (if applicable)
- `RuleId`
- `RiskScore`
- `TimeGenerated`
- Clear `HunterDirective`

Sensors must be independently deployable, suppressible, and tunable.

---

# LAYER 2 — CORRELATION (NARRATIVE STITCHING)

We do NOT correlate everything inside the detection rule.

Narrative stitching happens at the **incident layer**.

## 3.1 Correlation Inputs

Correlation uses:

- Entity Mapping (Account, Host, IP, FileHash, AppId)
- Time windows appropriate to tactic
- Grouping keys
- Stage classification

---

## 3.2 Time Window Guidance

Execution → C2:  
Minutes to hours

Persistence → Execution:  
Hours to days

Lateral Movement burst:  
Minutes to hours

Persistence hold-open window:  
Up to 72 hours

Timing mismatches must not break detection.

---

## 3.3 Grouping Keys

- Same `DeviceId` + same `Account`
- Same `SourceIP` → multiple `TargetHosts`
- Same `SHA256` seen across hosts (burst/radius)

---

## 3.4 Sentinel Implementation Options

- Incident grouping settings + entity mapping
OR
- Dedicated correlation analytics rule:
  - “2+ truths across stages” within defined window

Narrative is built from sensor truths — not assumptions.

---

# LAYER 3 — INCIDENT SCORING (WHEN STORY BECOMES REAL)

An incident becomes operationally real when:

- Multiple truths converge  
OR
- A single high-severity truth fires (e.g., confirmed LSASS access)

---

## 4.1 Incident Score Model

Compute incident score from:

- Stage count (distinct truths fired)
- Maximum severity
- Burst / radius (cross-host or cross-account)
- Rarity
- Privileged account involvement

This prevents:

- Ghost chains
- Over-correlation
- Narrative hallucination

---

# 5. CONCRETE IMPLEMENTATION EXAMPLE

## Deployed Sensors

1. PowerShell Suspicious Primitive (Execution)
2. Writable Path Drop + Exec (Ingress)
3. TaskCache Persistence (Persistence)
4. services.exe Uncommon Child After Inbound SMB (Lateral)
5. Outbound Rare Domain From Non-browser (C2)

---

## Correlation Logic

If:
- Same `DeviceId`
- 2+ of {1,2,3,5}
- Within 6 hours

→ Create / raise incident

If:
- Same `SourceIP`
- 3+ hosts trigger {4}
- Within 30 minutes

→ Treat as lateral campaign

If:
- Persistence truth {3} fires

→ Keep incident open for 72 hours
→ Attach later Execution/C2 truths

---

## Result

- Sensors remain clean
- Narrative assembled reliably
- Timing mismatches tolerated
- Persistence preceding execution does not break detection

---

# 6. PRODUCTION-GRADE REQUIREMENTS

## 6.1 Stable Joins Only

- Small → small joins (pre-summarized)
OR
- Avoid joins using initiating process fields

No blind large joins.

---

## 6.2 Telemetry Gap Tolerance

If one sensor misses, correlation still builds story.

Detection does not collapse due to single failure.

---

## 6.3 Noise Containment

Each sensor:

- Has independent suppression model
- Does not rely on global brittle allowlists
- Uses scoring gates where appropriate

---

## 6.4 Analyst-Ready Output

Each sensor must include:

- Clear pivot guidance
- Clear next investigative step
- Entity mapping for expansion

Correlation layer provides the story.

---

# 7. OPERATIONAL BLUEPRINT

To implement at scale:

### Build

1. Sensors watchlist/table:
   - RuleId
   - Stage
   - DefaultWindow
   - Weight

2. Correlation analytics rule:
   - Pulls last X hours of alerts
   - Computes incident score
   - Groups by entity type

3. Grouping rules:
   - Host
   - User
   - IP
   - Hash

4. Playbooks:
   - Whois enrichment
   - Device risk context
   - Sign-in context
   - Auto-attach intelligence

---

# 8. CRITICAL ENGINEERING CONSIDERATIONS

Detection must explicitly consider:

- Correlation latency
- Double counting incidents
- Ingestion failure
- Schema drift
- Noise gates
- Production refactoring
- SOC workflow impact
- Duplicate suppression

---

# 9. ENGINEERING SEPARATIONS (MANDATORY)

Always separate:

- Primitive vs Composite
- Alert vs Narrative
- Substrate vs Incident
- Sensor vs Story
- Detection vs Workflow
- Truth vs Reinforcement

Never collapse all layers into one monolithic rule.

---

# 10. DESIGN DOCTRINE SUMMARY

Detection begins at:

First principles → Minimum truth → Atomic sensor.

Narrative emerges from:

Convergence → Entity stitching → Incident scoring.

Production maturity requires:

Latency tolerance  
Noise containment  
Operational clarity  
Stable joins  
SOC-aligned workflow  

This is the Production Attack Narrative Pipeline.
