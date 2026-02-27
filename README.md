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

If the minimum truth does not exist, the attack does not exist.

Everything else is:

- Reinforcement  
- Confidence weighting  
- Narrative stitching  
- Incident shaping  

But never truth.

This framework exists to prevent:

- Ghost chains  
- Brittle joins  
- Monolithic kill-chain queries  
- Artificial correlation  
- Narrative hallucination  

We explicitly separate:

- Primitive vs Composite  
- Alert vs Incident  
- Sensor vs Narrative  
- Substrate vs Story  
- Truth vs Reinforcement  

If those boundaries collapse, detection collapses.

---

# 2. THE THREE-LAYER PRODUCTION MODEL

This model exists because enterprise telemetry is imperfect.

Attacks are non-linear.  
Telemetry is delayed.  
Noise is constant.  
Correlation windows drift.

So we separate detection into **three independent but cooperative layers**.

---

# LAYER 1 — SENSORS (ATOMIC TRUTHS)

Sensors are **always-on truth detectors**.

They are not kill-chain builders.  
They are not story tellers.  
They are not intelligence reports.

They are simple, clear, and bounded.

Each sensor:

- Anchors to one truth surface
- Lives in one telemetry domain
- Has its own noise model
- Can stand alone

If a sensor needs five joins across three tables to prove truth, the truth anchor is wrong.

---

## 2.1 What a Sensor Really Is

A sensor is a behavioural proof point.

Example:

- `RegistryValueSet` under TaskCache → persistence substrate exists.
- `services.exe` spawning uncommon child → service execution surface triggered.
- PowerShell with encoded runtime primitive → execution intent exists.
- Outbound connection from non-browser to rare domain → C2 surface exists.

Each of those is self-contained truth.

They may be noisy alone — but they are real.

---

## 2.2 Sensor Categories (Endpoint-Centric Model)

### Execution
Execution sensors answer:
> “Did something actually run that indicates attacker intent?”

Examples:
- Script host + encoded runtime logic
- LOLBin invoked with suspicious command primitives
- Abnormal parent-child lineage divergence

Execution truth is immediate.  
It does not require network or persistence to be valid.

---

### Ingress / Tool Transfer
Ingress sensors answer:
> “Did tooling enter the environment in executable form?”

Examples:
- File written to user-writable path with execution extension
- Download → immediate execution chain
- Rare binary drop from uncommon parent

Ingress does not require persistence to be malicious.

---

### Persistence
Persistence sensors answer:
> “Has an attacker modified state to survive reboot or logon?”

Each surface is separate truth:

- Run key write
- TaskCache artifact
- Service ImagePath modification

These are distinct ecosystems.

Never collapse them into one “Persistence Mega Rule.”

---

### Privilege Escalation
Privilege escalation sensors prove:
> “Was elevated capability materially obtained or manipulated?”

Examples:
- Token manipulation truth
- UAC bypass truth
- Suspicious handle access on protected processes

PrivEsc truth is rare but high impact.

---

### Lateral Movement
Each mechanism is a cousin:

- SMB service execution
- WMI remote execution
- WinRM execution

Same attacker goal.  
Different noise domains.  
Separate sensors.

---

### Command & Control
C2 sensors prove:
> “Did outbound communication occur in a way that departs from normal execution surfaces?”

Examples:
- Outbound from non-browser process
- Rare domain from signed system binary
- Suspicious protocol pattern

C2 is not defined by rarity alone.  
It is defined by **process context + outbound behavior.**

---

## 2.3 Sensor Output Requirements (Non-Negotiable)

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

If the rule does not produce pivot guidance, it is not production-ready.

Sensors must be:

- Independently deployable
- Independently suppressible
- Independently tunable
- Independent from correlation success

---

# LAYER 2 — CORRELATION (NARRATIVE STITCHING)

Correlation does not create truth.

Correlation assembles truths.

This layer exists because attackers operate across stages — but detection should not collapse into monolithic dependency.

We do NOT correlate everything inside a detection rule.

We correlate at the **incident layer**.

---

## 3.1 What Correlation Is Allowed To Do

Correlation may:

- Group truths by entity
- Count stage diversity
- Shape response priority
- Extend investigation windows

Correlation may NOT:

- Manufacture missing evidence
- Require all stages to occur
- Break detection if one truth is delayed
- Assume linear kill chains

---

## 3.2 Time Window Doctrine

Attack stages have different temporal realities.

Execution → C2  
Minutes to hours

Persistence → Execution  
Hours to days

Lateral burst  
Minutes

Persistence hold-open  
Up to 72 hours

Correlation windows must reflect attacker behavior — not analyst convenience.

If correlation fails due to strict windows, the window is wrong.

---

## 3.3 Grouping Keys (Operational Reality)

Narrative grouping may use:

- Same `DeviceId` + `Account`
- Same `SourceIP` across hosts
- Same `SHA256` across devices
- Same AppId (identity domain)

Grouping is entity-driven.

Never correlate purely on time proximity without entity alignment.

---

## 3.4 Sentinel Implementation Options

Two valid production patterns:

### Option A — Native Incident Grouping
Use Sentinel incident grouping + entity mapping.

### Option B — Dedicated Correlation Rule
Build a lightweight analytics rule that:
- Pulls recent sensor alerts
- Counts stage diversity
- Computes incident score

Both are acceptable.

What is not acceptable:
- One mega KQL rule attempting to prove full kill-chain in a single query.

---

# LAYER 3 — INCIDENT SCORING (WHEN STORY BECOMES REAL)

An incident becomes operationally meaningful when:

- Multiple distinct truths converge  
OR  
- A single high-severity truth fires  

Example high-severity truth:
- Confirmed LSASS access  
- Silent TaskCache persistence  
- Driver load from suspicious path  

Incident scoring is simple by design.

---

## 4.1 Incident Score Components

Incident score may include:

- Stage count (distinct truths)
- Maximum sensor severity
- Burst / lateral radius
- Organizational rarity
- Privileged account involvement

This prevents:

- Ghost chains  
- Over-correlation  
- Narrative inflation  

The incident is shaped by truth density, not imagination.

---

# 5. CONCRETE IMPLEMENTATION EXAMPLE

## Deployed Sensors

1. PowerShell Suspicious Primitive (Execution)
2. Writable Path Drop + Exec (Ingress)
3. TaskCache Persistence (Persistence)
4. services.exe Uncommon Child After Inbound SMB (Lateral)
5. Outbound Rare Domain From Non-browser (C2)

Each one stands alone.

Each one is valid independently.

---

## Correlation Logic

If:
- Same `DeviceId`
- 2+ of {Execution, Ingress, Persistence, C2}
- Within 6 hours

→ Create / escalate incident

If:
- Same `SourceIP`
- 3+ hosts trigger Lateral sensor
- Within 30 minutes

→ Lateral campaign incident

If:
- Persistence truth fires

→ Keep incident open for 72 hours  
→ Attach subsequent execution/C2 truths  

This tolerates non-linear attack order.

---

## Result

- Sensors remain clean
- Narrative assembled reliably
- Timing mismatches tolerated
- Detection does not collapse under latency
- Attack variance does not break logic

---

# 6. PRODUCTION-GRADE REQUIREMENTS

## 6.1 Stable Joins Only

- Small → small joins
- Pre-summarized prevalence joins
- Prefer initiating process fields

Never join raw telemetry tables blindly.

---

## 6.2 Telemetry Gap Tolerance

Production detection must survive:

- Missed events
- Endpoint offline gaps
- Connector delays
- Partial ingestion

If detection requires perfect telemetry to work, it will fail.

---

## 6.3 Noise Containment

Each sensor must have:

- Its own suppression model
- Its own prevalence weighting
- Its own confidence threshold

Never rely on global allowlists to fix bad truth anchors.

---

## 6.4 Analyst-Ready Output

Sensors must tell analysts:

- Why this fired (truth)
- What reinforces it (evidence)
- What to pivot to next
- When to escalate

Correlation layer provides story context.

Sensor provides action.

---

# 7. OPERATIONAL BLUEPRINT

To implement at scale:

1. Maintain a Sensors Table:
   - RuleId
   - Stage
   - Default correlation window
   - Weight

2. Maintain a Correlation Rule:
   - Pull recent sensor alerts
   - Compute stage diversity
   - Apply simple incident scoring

3. Configure Grouping:
   - Host
   - User
   - IP
   - Hash

4. Attach Playbooks:
   - WHOIS enrichment
   - Device risk
   - Sign-in context
   - Threat intel attachment

Sensors detect.  
Correlation narrates.  
Playbooks accelerate.

---

# 8. CRITICAL ENGINEERING CONSIDERATIONS

Production detection must explicitly consider:

- Correlation latency
- Duplicate incident suppression
- Double counting same truth
- Ingestion drift
- Schema evolution
- Noise gates
- SOC workflow impact

Engineering is not just logic.  
It is operational survivability.

---

# 9. MANDATORY SEPARATIONS

Never collapse:

- Primitive vs Composite
- Alert vs Narrative
- Sensor vs Incident
- Truth vs Reinforcement
- Detection vs Workflow

When layers merge, brittleness begins.

---

# 10. FINAL DOCTRINE

Detection begins with:

First Principles → Minimum Truth → Atomic Sensor

Confidence emerges through:

Reinforcement → Convergence → Scoring

Narrative emerges through:

Entity stitching → Stage diversity → Incident shaping

Production maturity requires:

Latency tolerance  
Noise containment  
Stable joins  
Clear analyst directives  
Strict layer separation  

This is the Production Attack Narrative Pipeline.

flowchart TD
  %% ============================================================
  %% Production Attack Narrative Pipeline (Minimum Truth → Narrative)
  %% Author: Ala Dabat
  %% Model: Sensors (Truth) → Correlation (Entities) → Scoring → Workflow
  %% ============================================================

  subgraph L1["LAYER 1 — SENSORS (Atomic Minimum Truths)"]
    S1["Sensor A: Execution Truth<br/>e.g., PowerShell/LOLBIN high-risk primitive<br/><b>Outputs:</b> DeviceId, Account, Process, SHA, RuleId, Stage, RiskScore, Time, HunterDirective"]
    S2["Sensor B: Ingress / Tool Transfer Truth<br/>e.g., writable-path drop with exec intent<br/><b>Outputs:</b> DeviceId, Account, File, SHA, RuleId, Stage, RiskScore, Time, HunterDirective"]
    S3["Sensor C: Persistence Truth<br/>e.g., RunKey/TaskCache/Service ImagePath write<br/><b>Outputs:</b> DeviceId, Account, Key/Value, WriterProc, RuleId, Stage, RiskScore, Time, HunterDirective"]
    S4["Sensor D: Lateral Truth<br/>e.g., remote service exec / WMI / WinRM (cousins)<br/><b>Outputs:</b> SourceIP, TargetHost(s), Account, Proc, RuleId, Stage, RiskScore, Time, HunterDirective"]
    S5["Sensor E: C2 Truth<br/>e.g., outbound from abnormal proc / rare infra pattern<br/><b>Outputs:</b> DeviceId, Process, RemoteDomain/IP, RuleId, Stage, RiskScore, Time, HunterDirective"]
  end

  subgraph BUS["ALERT BUS / LOG PIPELINE"]
    B1["Sentinel Analytics Alerts<br/>or Custom 'Sensors' Table<br/>(Normalized schema: Stage, RuleId, Entities, RiskScore)"]
  end

  subgraph L2["LAYER 2 — CORRELATION (Narrative Stitching)"]
    C0["Entity Mapping (Non-Negotiable)<br/>Host / User / IP / Hash / AppId"]
    C1["Entity Clustering<br/><b>Group Keys:</b><br/>• DeviceId+Account<br/>• SourceIP→Targets<br/>• SHA burst across hosts"]
    C2["Time Windows (Tactic-Realistic)<br/>Execution→C2: min→hrs<br/>Persistence→Execution: hrs→days<br/>Lateral burst: min→hrs<br/>Persistence hold-open: up to 72h"]
    C3["Stage Diversity Check<br/><b>Count distinct Stage</b><br/>(Execution, Ingress, Persistence, Lateral, C2, etc.)"]
    C4["Dedupe Fingerprint<br/>Prevent double counting:<br/>DeviceId+Account+RuleId(+SHA)+TimeBin<br/>Suppress duplicates inside incident"]
  end

  subgraph L3["LAYER 3 — INCIDENT SCORING (When Story Becomes Real)"]
    I1["Incident Score Engine<br/><b>Inputs:</b><br/>• StageCount (distinct)<br/>• MaxSeverity/RiskScore<br/>• Burst/Radius<br/>• Rarity/Prevalence<br/>• Privileged user involvement"]
    I2["Incident Thresholds<br/>• 1 high-severity truth alone → Incident<br/>• 2+ stages converge → Incident<br/>• Lateral radius threshold → Campaign Incident"]
    I3["Incident Output<br/>Unified Attack Story (Case/Incident)<br/>Entities + Timeline + Confidence + Next Actions"]
  end

  subgraph OPS["SOC WORKFLOW (Actionable Operations)"]
    O1["Triage Queue<br/>Single incident view, not alert spam"]
    O2["HunterDirectives (Inline)<br/>What fired / why / pivots / scope"]
    O3["Enrichment Playbooks<br/>WHOIS, TI, device risk, sign-in context, etc."]
    O4["Response / IR<br/>Contain, isolate, block, hunt for cousins, etc."]
  end

  %% -----------------------------
  %% Flow
  %% -----------------------------
  S1 --> B1
  S2 --> B1
  S3 --> B1
  S4 --> B1
  S5 --> B1

  B1 --> C0 --> C1 --> C2 --> C3 --> C4 --> I1 --> I2 --> I3 --> O1 --> O2 --> O3 --> O4

  %% -----------------------------
  %% Notes (Core Doctrine)
  %% -----------------------------
  N1["Key Doctrine:<br/><b>MITRE is classification, not correlation.</b><br/>Narrative is built from: Entities + Stage diversity + Time realism.<br/>Sensors stay clean; story is assembled reliably."]:::note
  C3 --- N1

  classDef note fill:#111,stroke:#999,color:#fff;

Operating model.
