/**
 * CREDTRACE V2 - Module A: Controlled Attacker Simulator Interactivity
 * Advanced Adversary Simulation Console with real-time terminal & phase tracker
 */

document.addEventListener("DOMContentLoaded", () => {
  let activeSessionId = localStorage.getItem("sim_session_id") || "";
  let isSimulating = false;
  let currentPhase = 0;

  const terminalBody = document.getElementById("terminal-output");
  const deviceLabelInput = document.getElementById("device-label-input");
  const secretInput = document.getElementById("simulator-secret-input");
  const sessionDisplay = document.getElementById("sim-session-id");
  const statusDisplay = document.getElementById("sim-status");
  const containmentAlert = document.getElementById("containment-banner");
  const phaseIndicator = document.getElementById("attack-phase-name");
  const phaseProgress = document.getElementById("attack-phase-progress");

  // Attack Phase Definitions
  const PHASES = [
    { name: "STANDBY / RECONNAISSANCE", pct: 10 },
    { name: "INITIAL ACCESS & AUTHENTICATION", pct: 30 },
    { name: "INTERNAL DISCOVERY & ENUMERATION", pct: 55 },
    { name: "RESTRICTED DATA EXFILTRATION ATTEMPT", pct: 85 },
    { name: "CONTAINED / INTERCEPTED", pct: 100 }
  ];

  updatePhase(0);
  if (activeSessionId && sessionDisplay) sessionDisplay.textContent = activeSessionId;

  // 1. Terminal Logging Helper
  function logTerminal(message, type = "normal", code = null) {
    if (!terminalBody) return;
    const now = new Date().toTimeString().split(" ")[0];
    const entry = document.createElement("div");
    entry.className = "log-entry";

    let codeHtml = "";
    if (code) {
      const codeClass = code === 200 ? "log-code-200" : code === 401 ? "log-code-401" : "log-code-403";
      codeHtml = `<span class="${codeClass}">[HTTP ${code}]</span>`;
    }

    let colorStyle = "#94a3b8";
    if (type === "success") colorStyle = "var(--accent-green)";
    if (type === "warning") colorStyle = "var(--accent-amber)";
    if (type === "critical") colorStyle = "var(--accent-red)";
    if (type === "cmd") colorStyle = "var(--accent-cyan)";

    entry.innerHTML = `
      <span class="log-ts">[${now}]</span>
      ${codeHtml}
      <span style="color:${colorStyle};">${message}</span>
    `;

    terminalBody.appendChild(entry);
    terminalBody.scrollTop = terminalBody.scrollHeight;
  }

  function updatePhase(idx) {
    currentPhase = idx;
    const p = PHASES[idx] || PHASES[0];
    if (phaseIndicator) phaseIndicator.textContent = p.name;
    if (phaseProgress) phaseProgress.style.width = `${p.pct}%`;
  }

  // 2. Action Handlers
  document.getElementById("btn-sim-auth")?.addEventListener("click", async () => {
    const room = CREDTRACE.getRoom();
    const deviceLabel = deviceLabelInput?.value.trim() || "LAPTOP-02-SIMULATOR";
    const secret = secretInput?.value.trim();

    if (!secret) {
      logTerminal("ERROR: Synthetic secret must be provided to authenticate.", "critical");
      CREDTRACE.showToast("Missing Secret", "Paste the synthetic token from Company Portal.", "warning");
      return;
    }

    logTerminal(`Sending adversary authentication probe to room '${room}'...`, "cmd");
    try {
      const resp = await fetch("/api/simulator/auth", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          room_id: room,
          device_label: deviceLabel,
          secret: secret
        })
      });
      const data = await resp.json();
      if (resp.ok && data.success) {
        activeSessionId = data.data.session_id;
        localStorage.setItem("sim_session_id", activeSessionId);
        if (sessionDisplay) sessionDisplay.textContent = activeSessionId;
        if (statusDisplay) statusDisplay.textContent = "AUTHENTICATED";
        updatePhase(1);
        logTerminal(`Authentication SUCCESS! Issued Session Token: ${activeSessionId} | Event ID: ${data.event_id}`, "success", 200);
      } else {
        logTerminal(`Authentication DENIED: ${data.message} | Event ID: ${data.event_id}`, "critical", data.status_code);
        if (data.status_code === 403) {
          triggerContainmentUI();
        }
      }
    } catch (err) {
      logTerminal(`Network / Server error: ${err.message}`, "critical");
    }
  });

  document.getElementById("btn-sim-customers")?.addEventListener("click", async () => {
    const room = CREDTRACE.getRoom();
    const deviceLabel = deviceLabelInput?.value.trim() || "LAPTOP-02-SIMULATOR";
    logTerminal(`Requesting customer freight manifest records from database...`, "cmd");
    try {
      const resp = await fetch(`/api/simulator/customers?room=${encodeURIComponent(room)}&session_id=${encodeURIComponent(activeSessionId || 'sess_default')}&device_label=${encodeURIComponent(deviceLabel)}`);
      const data = await resp.json();
      if (data.success) {
        updatePhase(2);
        logTerminal(`Retrieved ${data.data.length} confidential customer manifests. Ex: Bavarian Logistics AG, Pacific Transshipment. | Event: ${data.event_id}`, "success", 200);
      } else {
        logTerminal(`Access Blocked: ${data.message} | Event: ${data.event_id}`, "critical", data.status_code);
        if (data.status_code === 403) triggerContainmentUI();
      }
    } catch (e) {
      logTerminal(`Error: ${e.message}`, "critical");
    }
  });

  document.getElementById("btn-sim-vendors")?.addEventListener("click", async () => {
    const room = CREDTRACE.getRoom();
    const deviceLabel = deviceLabelInput?.value.trim() || "LAPTOP-02-SIMULATOR";
    logTerminal(`Enumerating vendor integration registry...`, "cmd");
    try {
      const resp = await fetch(`/api/simulator/vendors?room=${encodeURIComponent(room)}&session_id=${encodeURIComponent(activeSessionId || 'sess_default')}&device_label=${encodeURIComponent(deviceLabel)}`);
      const data = await resp.json();
      if (data.success) {
        updatePhase(2);
        logTerminal(`Enumerated ${data.data.length} vendor API endpoints (BlueVault, OceanTrack AIS, CustomsPort EDI). | Event: ${data.event_id}`, "success", 200);
      } else {
        logTerminal(`Access Blocked: ${data.message}`, "critical", data.status_code);
        if (data.status_code === 403) triggerContainmentUI();
      }
    } catch (e) {
      logTerminal(`Error: ${e.message}`, "critical");
    }
  });

  document.getElementById("btn-sim-export")?.addEventListener("click", async () => {
    const room = CREDTRACE.getRoom();
    const deviceLabel = deviceLabelInput?.value.trim() || "LAPTOP-02-SIMULATOR";
    logTerminal(`ATTEMPTING RESTRICTED BULK DATA EXFILTRATION (ALL_GLOBAL_CUSTOMERS_AND_TRANSACTIONS)...`, "critical");
    try {
      const resp = await fetch("/api/simulator/export", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          room_id: room,
          session_id: activeSessionId || "sess_sim_01",
          device_label: deviceLabel
        })
      });
      const data = await resp.json();
      updatePhase(3);
      logTerminal(`SECURITY POLICY INTERCEPTION: ${data.message} | Event: ${data.event_id}`, "critical", data.status_code);
      if (data.alert_triggered) {
        logTerminal(`[DETECTION ALERT GENERATED] ${data.alert_triggered.rule_name} (Severity: ${data.alert_triggered.severity})`, "warning");
      }
    } catch (e) {
      logTerminal(`Error: ${e.message}`, "critical");
    }
  });

  document.getElementById("btn-sim-invalid")?.addEventListener("click", async () => {
    const room = CREDTRACE.getRoom();
    const deviceLabel = deviceLabelInput?.value.trim() || "LAPTOP-02-SIMULATOR";
    logTerminal(`Testing invalid synthetic key probe 'sec_invalid_attacker_probe'...`, "warning");
    try {
      const resp = await fetch(`/api/simulator/test-invalid?room=${encodeURIComponent(room)}&device_label=${encodeURIComponent(deviceLabel)}`, {
        method: "POST"
      });
      const data = await resp.json();
      logTerminal(`Probe rejected: ${data.message} | Event: ${data.event_id}`, "critical", data.status_code);
    } catch (e) {
      logTerminal(`Error: ${e.message}`, "critical");
    }
  });

  // 3. Automated Scripted Scenario Runner
  document.getElementById("btn-run-script")?.addEventListener("click", async () => {
    if (isSimulating) return;
    isSimulating = true;
    logTerminal("=== INITIATING CONTROLLED ADVERSARY SIMULATION SEQUENCE ===", "cmd");
    
    // Auto-fetch current secret if input empty
    if (!secretInput?.value.trim()) {
      try {
        const resp = await fetch(`/api/portal/credential?room=${encodeURIComponent(CREDTRACE.getRoom())}`);
        if (resp.ok) {
          const cred = await resp.json();
          if (secretInput) secretInput.value = cred.secret_display;
        }
      } catch (e) {}
    }

    setTimeout(() => {
      document.getElementById("btn-sim-auth")?.click();
      setTimeout(() => {
        document.getElementById("btn-sim-vendors")?.click();
        setTimeout(() => {
          document.getElementById("btn-sim-customers")?.click();
          setTimeout(() => {
            document.getElementById("btn-sim-export")?.click();
            isSimulating = false;
            logTerminal("=== ATTACK SEQUENCE COMPLETED - AWAITING INVESTIGATOR CONTAINMENT ===", "cmd");
          }, 1800);
        }, 1500);
      }, 1500);
    }, 800);
  });

  document.getElementById("btn-clear-terminal")?.addEventListener("click", () => {
    if (terminalBody) terminalBody.innerHTML = "";
    logTerminal("Terminal buffer reset. Ready for adversary telemetry.", "normal");
  });

  // 4. Containment Notification UI
  function triggerContainmentUI() {
    if (containmentAlert) containmentAlert.style.display = "block";
    if (statusDisplay) statusDisplay.textContent = "CONTAINED (REVOKED)";
    updatePhase(4);
    logTerminal(">>> [CONTAINMENT ACTIVATED] Credential bvk-7f3a was REVOKED by investigator. All further operations are blocked at backend! <<<", "critical", 403);
  }

  // 5. WebSocket Listeners
  CREDTRACE.on("containment", (msg) => {
    triggerContainmentUI();
  });

  CREDTRACE.on("reset", () => {
    if (containmentAlert) containmentAlert.style.display = "none";
    if (statusDisplay) statusDisplay.textContent = "STANDBY";
    updatePhase(0);
    logTerminal("Room reset detected. Session reset.", "normal");
  });
});
