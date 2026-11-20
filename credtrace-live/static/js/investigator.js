/**
 * CREDTRACE V2 - Module B: Investigator Command Centre & Digital Forensics
 * Live enterprise SOC dashboard with Chart.js analytics, SHA-256 hash-chain verification,
 * real-time threat detection alerts, and server-side containment enforcement.
 */

document.addEventListener("DOMContentLoaded", () => {
  let charts = {
    timeline: null,
    ratio: null,
    categories: null
  };

  let allEvents = [];
  let allAlerts = [];
  let autoScrollFeed = true;

  // DOM Elements
  const feedContainer = document.getElementById("events-feed-body");
  const alertsContainer = document.getElementById("alerts-list-container");
  const correlationContainer = document.getElementById("correlation-matrix-container");
  const auditContainer = document.getElementById("audit-verification-output");
  const riskGaugeVal = document.getElementById("kpi-risk-score");
  const riskProgress = document.getElementById("kpi-risk-bar");
  const eventsCount = document.getElementById("kpi-events-count");
  const allowedCount = document.getElementById("kpi-allowed-count");
  const deniedCount = document.getElementById("kpi-denied-count");
  const alertsCount = document.getElementById("kpi-alerts-count");
  const credStatusKpi = document.getElementById("kpi-credential-status");

  // Tab Navigation Handling
  document.querySelectorAll(".nav-tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const targetPane = document.getElementById(`pane-${btn.dataset.tab}`);
      if (targetPane) targetPane.classList.add("active");

      // Trigger lazy loads
      if (btn.dataset.tab === "correlation") loadCorrelations();
      if (btn.dataset.tab === "audit") runAuditVerification();
      if (btn.dataset.tab === "credentials") loadCredentialDetails();
    });
  });

  // 1. Initialize Dashboard Data
  initDashboard();

  async function initDashboard() {
    const room = CREDTRACE.getRoom();
    initCharts();
    await refreshOverview();
    await refreshEvents();
    await refreshAlerts();
    await loadCorrelations();
    await loadCredentialDetails();
  }

  // 2. Fetch and Render Real Overview Statistics
  async function refreshOverview() {
    const room = CREDTRACE.getRoom();
    try {
      const resp = await fetch(`/api/investigator/overview?room=${encodeURIComponent(room)}`);
      if (resp.ok) {
        const stats = await resp.json();
        renderKPIs(stats);
        updateCharts(stats);
      }
    } catch (err) {
      console.error("Overview refresh failed:", err);
    }
  }

  function renderKPIs(stats) {
    if (eventsCount) eventsCount.textContent = stats.total_events;
    if (allowedCount) allowedCount.textContent = stats.allowed_requests;
    if (deniedCount) deniedCount.textContent = stats.denied_requests;
    if (alertsCount) alertsCount.textContent = stats.threat_alerts;
    
    const risk = stats.risk_score || 0;
    if (riskGaugeVal) riskGaugeVal.textContent = `${risk} / 100`;
    if (riskProgress) {
      riskProgress.style.width = `${risk}%`;
      riskProgress.style.backgroundColor = risk > 70 ? "var(--accent-red)" : risk > 35 ? "var(--accent-amber)" : "var(--accent-green)";
    }

    if (credStatusKpi) {
      const isRev = stats.credential_status?.is_revoked || stats.revoked_credentials > 0;
      credStatusKpi.textContent = isRev ? "CONTAINED (REVOKED)" : "ACTIVE (MONITORING)";
      credStatusKpi.className = `badge ${isRev ? 'badge-critical' : 'badge-low'}`;
    }
  }

  // 3. Chart.js Visualizations
  function initCharts() {
    const timelineCtx = document.getElementById("chart-timeline")?.getContext("2d");
    const ratioCtx = document.getElementById("chart-ratio")?.getContext("2d");

    if (timelineCtx && !charts.timeline) {
      charts.timeline = new Chart(timelineCtx, {
        type: "line",
        data: {
          labels: ["00:00", "00:05", "00:10", "00:15", "00:20"],
          datasets: [{
            label: "Telemetry Events",
            data: [0, 0, 0, 0, 0],
            borderColor: "#06b6d4",
            backgroundColor: "rgba(6, 182, 212, 0.15)",
            tension: 0.35,
            fill: true
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#64748b" } },
            y: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#64748b", stepSize: 1 } }
          }
        }
      });
    }

    if (ratioCtx && !charts.ratio) {
      charts.ratio = new Chart(ratioCtx, {
        type: "doughnut",
        data: {
          labels: ["Allowed", "Denied (Policy / Revoked)"],
          datasets: [{
            data: [1, 0],
            backgroundColor: ["#10b981", "#ef4444"],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { position: "bottom", labels: { color: "#94a3b8", font: { size: 11 } } }
          }
        }
      });
    }
  }

  function updateCharts(stats) {
    if (charts.ratio && stats.allowed_vs_denied) {
      charts.ratio.data.datasets[0].data = [
        stats.allowed_vs_denied.ALLOWED || 0,
        stats.allowed_vs_denied.DENIED || 0
      ];
      charts.ratio.update();
    }

    if (charts.timeline && stats.activity_timeline) {
      const labels = stats.activity_timeline.map(t => t.timestamp ? t.timestamp.substring(11, 19) : "");
      const counts = stats.activity_timeline.map((_, i) => i + 1);
      charts.timeline.data.labels = labels.slice(-8);
      charts.timeline.data.datasets[0].data = counts.slice(-8);
      charts.timeline.update();
    }
  }

  // 4. Live Events Feed Handling
  async function refreshEvents() {
    const room = CREDTRACE.getRoom();
    try {
      const resp = await fetch(`/api/investigator/events?room=${encodeURIComponent(room)}&limit=50`);
      if (resp.ok) {
        allEvents = await resp.json();
        renderEventFeed();
      }
    } catch (e) {
      console.error("Failed to load events:", e);
    }
  }

  function renderEventFeed() {
    if (!feedContainer) return;
    if (allEvents.length === 0) {
      feedContainer.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-dim); padding:24px;">Awaiting live adversary telemetry...</td></tr>`;
      return;
    }

    feedContainer.innerHTML = allEvents.slice(-25).reverse().map(e => {
      const decisionClass = e.decision === "ALLOWED" ? "badge-low" : "badge-critical";
      const shortHash = e.current_hash ? `${e.current_hash.substring(0, 8)}...` : "-";
      return `
        <tr>
          <td class="mono" style="color:var(--accent-cyan); font-weight:700;">${e.event_id}</td>
          <td class="mono" style="color:var(--text-dim);">${e.timestamp ? e.timestamp.substring(11, 19) : "-"}</td>
          <td><b>${e.action}</b><br/><span style="font-size:10px; color:var(--text-dim);">${e.resource}</span></td>
          <td><span class="badge ${decisionClass}">${e.decision}</span> <span class="mono" style="font-size:11px;">[${e.http_status}]</span></td>
          <td class="mono" style="font-size:11px;">${e.device_label || 'Unknown'}</td>
          <td class="mono" style="color:var(--text-dim); font-size:11px;" title="${e.current_hash}">${shortHash}</td>
        </tr>
      `;
    }).join("");

    if (autoScrollFeed && feedContainer.parentElement) {
      feedContainer.parentElement.scrollTop = feedContainer.parentElement.scrollHeight;
    }
  }

  // 5. Threat Alerts Rendering
  async function refreshAlerts() {
    const room = CREDTRACE.getRoom();
    try {
      const resp = await fetch(`/api/investigator/alerts?room=${encodeURIComponent(room)}`);
      if (resp.ok) {
        allAlerts = await resp.json();
        renderAlerts();
      }
    } catch (e) {
      console.error("Alerts fetch error:", e);
    }
  }

  function renderAlerts() {
    if (!alertsContainer) return;
    if (allAlerts.length === 0) {
      alertsContainer.innerHTML = `<div style="color:var(--text-dim); padding:16px;">No active threat alerts triggered yet.</div>`;
      return;
    }

    alertsContainer.innerHTML = allAlerts.map(a => {
      const sevClass = a.severity === "Critical" ? "badge-critical" : a.severity === "High" ? "badge-high" : "badge-medium";
      return `
        <div style="background:rgba(20, 10, 15, 0.85); border:1px solid rgba(239, 68, 68, 0.3); border-radius:var(--radius-sm); padding:14px; margin-bottom:12px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
            <span style="font-weight:700; color:#fff; font-size:13px;">${a.alert_id}: ${a.rule_name}</span>
            <span class="badge ${sevClass}">${a.severity}</span>
          </div>
          <div style="font-size:12px; color:#fca5a5; margin-bottom:8px;">${a.description}</div>
          <div style="font-size:11px; color:var(--text-muted); background:rgba(0,0,0,0.3); padding:6px 10px; border-radius:var(--radius-sm);">
            <b>Recommended Response:</b> ${a.recommended_action}
          </div>
        </div>
      `;
    }).join("");
  }

  // 6. Multi-Source Correlation Matrix
  async function loadCorrelations() {
    const room = CREDTRACE.getRoom();
    try {
      const resp = await fetch(`/api/investigator/correlations?room=${encodeURIComponent(room)}`);
      if (resp.ok) {
        const findings = await resp.json();
        renderCorrelations(findings);
      }
    } catch (e) {
      console.error("Correlations fetch error:", e);
    }
  }

  function renderCorrelations(findings) {
    if (!correlationContainer) return;
    correlationContainer.innerHTML = findings.map(f => {
      const confClass = f.confidence.includes("Strong") ? "badge-critical" : f.confidence.includes("Partial") ? "badge-high" : "badge-medium";
      const evidenceList = f.evidence_points ? f.evidence_points.map(pt => `<li>${pt}</li>`).join("") : "";
      return `
        <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:var(--radius-md); padding:16px; margin-bottom:14px;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
            <span style="font-weight:700; color:#fff; font-size:14px;">${f.title}</span>
            <span class="badge ${confClass}">${f.confidence}</span>
          </div>
          <p style="font-size:12px; color:var(--text-muted); margin-bottom:10px;">${f.description}</p>
          <div style="font-size:11px; color:var(--text-dim); border-top:1px solid rgba(255,255,255,0.05); padding-top:8px;">
            <b style="color:var(--text-main);">Evidence Grounding:</b>
            <ul style="margin-left:18px; margin-top:4px;">${evidenceList}</ul>
          </div>
        </div>
      `;
    }).join("");
  }

  // 7. Cryptographic Tamper-Evident Hash Chain Audit
  async function runAuditVerification() {
    const room = CREDTRACE.getRoom();
    if (!auditContainer) return;
    auditContainer.innerHTML = `<div style="color:var(--text-dim); padding:16px;">Traversing SHA-256 hash chain from Genesis block...</div>`;

    try {
      const resp = await fetch(`/api/investigator/verify-audit?room=${encodeURIComponent(room)}`);
      if (resp.ok) {
        const data = await resp.json();
        const v = data.verification;
        const statusBadge = v.valid 
          ? `<span class="badge badge-low" style="font-size:13px;">CHAIN INTACT & VALID</span>`
          : `<span class="badge badge-critical" style="font-size:13px;">INTEGRITY VIOLATION</span>`;

        auditContainer.innerHTML = `
          <div style="background:rgba(16, 185, 129, 0.05); border:1px solid rgba(16, 185, 129, 0.3); border-radius:var(--radius-md); padding:18px; margin-bottom:16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
              <h4 style="color:#fff;">Cryptographic Ledger Verification</h4>
              ${statusBadge}
            </div>
            <div style="font-size:12px; line-height:1.7; color:var(--text-muted);">
              <div>Total Event Blocks Verified: <b>${v.total_verified}</b></div>
              <div>Genesis Block Hash: <span class="mono" style="color:var(--accent-cyan);">${v.genesis_hash}</span></div>
              <div>Latest Verified Hash: <span class="mono" style="color:var(--accent-green);">${v.latest_hash || 'N/A'}</span></div>
              <div style="margin-top:6px; color:#cbd5e1;"><b>Verification Result:</b> ${v.reason}</div>
            </div>
          </div>
          <div style="font-size:11px; color:var(--text-dim); line-height:1.5;">
            <b>Forensic Context:</b> SHA-256 hash chaining guarantees that any inserted, deleted, modified, or reordered security event 
            immediately breaks subsequent block hashes. Note that hash chaining proves sequence integrity, but cannot by itself prevent 
            privileged storage overwrite without write-once (WORM) storage controls.
          </div>
        `;
      }
    } catch (e) {
      auditContainer.innerHTML = `<div style="color:var(--accent-red);">Verification call failed: ${e.message}</div>`;
    }
  }

  document.getElementById("btn-run-audit-check")?.addEventListener("click", runAuditVerification);

  // 8. Credential Details Profile
  async function loadCredentialDetails() {
    const room = CREDTRACE.getRoom();
    try {
      const resp = await fetch(`/api/investigator/credentials?room=${encodeURIComponent(room)}`);
      if (resp.ok) {
        const cred = await resp.json();
        const isRev = cred.is_revoked || cred.status === "REVOKED";
        
        document.getElementById("cred-id-val").textContent = cred.credential_id;
        document.getElementById("cred-case-val").textContent = cred.case_id;
        document.getElementById("cred-ticket-val").textContent = cred.ticket_ref;
        document.getElementById("cred-hash-val").textContent = cred.secret_hash;
        document.getElementById("cred-created-val").textContent = cred.created_at;
        document.getElementById("cred-status-val").textContent = isRev ? "REVOKED (CONTAINED)" : "ACTIVE";
        document.getElementById("cred-status-val").className = `badge ${isRev ? 'badge-critical' : 'badge-low'}`;
        
        if (isRev && cred.revoked_at) {
          document.getElementById("cred-revocation-details").style.display = "block";
          document.getElementById("cred-revoked-at-val").textContent = cred.revoked_at;
          document.getElementById("cred-revoked-reason-val").textContent = cred.revocation_reason || "Adversary containment";
        } else {
          document.getElementById("cred-revocation-details").style.display = "none";
        }
      }
    } catch (e) {
      console.error("Failed to load credential details:", e);
    }
  }

  // 9. Containment Revocation Trigger
  async function executeRevocation() {
    const room = CREDTRACE.getRoom();
    const reasonInput = document.getElementById("revocation-reason-input");
    const reason = reasonInput?.value.trim() || "Immediate containment of suspected compromised credential (Incident CR-26-047)";

    try {
      const resp = await fetch("/api/investigator/revoke", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          room_id: room,
          credential_id: "bvk-7f3a",
          reason: reason,
          investigator_id: "SOC-CHEN-INVESTIGATOR"
        })
      });
      const data = await resp.json();
      if (resp.ok && data.success) {
        CREDTRACE.showToast("REVOCATION ENFORCED", `Credential bvk-7f3a revoked on server! Event: ${data.event_id}`, "critical");
        await refreshOverview();
        await refreshEvents();
        await loadCredentialDetails();
      }
    } catch (err) {
      console.error("Revocation call error:", err);
    }
  }

  document.getElementById("btn-header-revoke")?.addEventListener("click", () => {
    if (confirm("CONFIRM CONTAINMENT: Revoke credential bvk-7f3a immediately across all endpoints?")) {
      executeRevocation();
    }
  });

  document.getElementById("btn-pane-revoke")?.addEventListener("click", () => {
    executeRevocation();
  });

  // 10. Room Reset Handler
  document.getElementById("btn-reset-simulation")?.addEventListener("click", async () => {
    if (!confirm("RESET SIMULATION: Clear recorded events and return room to clean baseline state?")) return;
    const room = CREDTRACE.getRoom();
    try {
      const resp = await fetch("/api/investigator/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ room_id: room, admin_code: "crimeathon26" })
      });
      if (resp.ok) {
        await initDashboard();
        CREDTRACE.showToast("Room Reset", "Simulation state reset for clean demonstration.", "info");
      } else if (resp.status === 403) {
        CREDTRACE.showToast("Unauthorized", "Invalid administrator authorization code.", "critical");
      }
    } catch (e) {
      console.error("Reset failed:", e);
    }
  });

  // 11. Report Downloads (PDF & JSON)
  document.getElementById("btn-download-pdf")?.addEventListener("click", () => {
    const room = CREDTRACE.getRoom();
    window.open(`/api/reports/pdf?room=${encodeURIComponent(room)}`, "_blank");
  });

  document.getElementById("btn-download-json")?.addEventListener("click", () => {
    const room = CREDTRACE.getRoom();
    window.open(`/api/reports/json?room=${encodeURIComponent(room)}`, "_blank");
  });

  // 12. Real-Time WebSocket Listeners
  CREDTRACE.on("event", (evt, cred) => {
    allEvents.push(evt);
    renderEventFeed();
    refreshOverview();
  });

  CREDTRACE.on("alert", (alt) => {
    allAlerts.unshift(alt);
    renderAlerts();
    refreshOverview();
  });

  CREDTRACE.on("containment", () => {
    refreshOverview();
    loadCredentialDetails();
  });

  CREDTRACE.on("reset", () => {
    initDashboard();
  });
});
