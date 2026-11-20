/**
 * CREDTRACE V2 - Module A: Company Portal Interactivity
 * Harbor & Finch Freight Pvt. Ltd.
 */

document.addEventListener("DOMContentLoaded", () => {
  let currentUser = JSON.parse(localStorage.getItem("hf_portal_user") || "null");

  const authSection = document.getElementById("auth-section");
  const portalSection = document.getElementById("portal-main-section");
  const userGreeting = document.getElementById("user-greeting");
  const secretDisplay = document.getElementById("synthetic-secret-display");
  const credStatusBadge = document.getElementById("credential-status-badge");
  const ticketsContainer = document.getElementById("tickets-list");

  // 1. Initial State Check
  if (currentUser) {
    showPortal();
  } else {
    showLogin();
  }

  loadDemoUsers();
  loadCredential();
  loadTickets();

  // 2. Authentication Handling
  document.getElementById("login-form")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("username-input").value.trim();
    const password = document.getElementById("password-input").value.trim();
    await executeLogin(username, password);
  });

  document.getElementById("logout-btn")?.addEventListener("click", () => {
    localStorage.removeItem("hf_portal_user");
    currentUser = null;
    showLogin();
    CREDTRACE.showToast("Logged Out", "Signed out of Harbor & Finch portal.", "info");
  });

  async function executeLogin(username, password) {
    try {
      const resp = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const data = await resp.json();
      if (resp.ok && data.success) {
        currentUser = data.user;
        localStorage.setItem("hf_portal_user", JSON.stringify(currentUser));
        showPortal();
        CREDTRACE.showToast("Login Successful", data.message, "success");
      } else {
        CREDTRACE.showToast("Authentication Failed", data.detail || "Invalid credentials.", "critical");
      }
    } catch (err) {
      console.error("Login error:", err);
      CREDTRACE.showToast("Error", "Could not connect to authentication service.", "critical");
    }
  }

  async function loadDemoUsers() {
    try {
      const resp = await fetch("/api/auth/demo-users");
      const users = await resp.json();
      const container = document.getElementById("demo-users-pills");
      if (container && users.length > 0) {
        container.innerHTML = users.map(u => `
          <button type="button" class="btn btn-outline btn-sm" onclick="quickFillLogin('${u.username}', 'Password123!')">
            ${u.full_name} (${u.role})
          </button>
        `).join("");
      }
    } catch (e) {
      console.warn("Could not load demo users:", e);
    }
  }

  window.quickFillLogin = function (user, pass) {
    document.getElementById("username-input").value = user;
    document.getElementById("password-input").value = pass;
    executeLogin(user, pass);
  };

  function showLogin() {
    if (authSection) authSection.style.display = "block";
    if (portalSection) portalSection.style.display = "none";
  }

  function showPortal() {
    if (authSection) authSection.style.display = "none";
    if (portalSection) portalSection.style.display = "block";
    if (userGreeting && currentUser) {
      userGreeting.textContent = `${currentUser.full_name} [${currentUser.role} - ${currentUser.department}]`;
    }
  }

  // 3. Credential Exposure Handling
  async function loadCredential() {
    const room = CREDTRACE.getRoom();
    try {
      const resp = await fetch(`/api/portal/credential?room=${encodeURIComponent(room)}`);
      if (resp.ok) {
        const cred = await resp.json();
        updateCredentialUI(cred);
      }
    } catch (err) {
      console.error("Failed to load credential:", err);
    }
  }

  function updateCredentialUI(cred) {
    if (secretDisplay) secretDisplay.value = cred.secret_display || cred.synthetic_secret || "Not Available";
    if (credStatusBadge) {
      const isRevoked = cred.is_revoked || cred.status === "REVOKED";
      credStatusBadge.textContent = isRevoked ? "REVOKED (CONTAINED)" : "ACTIVE (VALID)";
      credStatusBadge.className = `badge ${isRevoked ? "badge-critical" : "badge-low"}`;
    }
  }

  document.getElementById("btn-copy-secret")?.addEventListener("click", () => {
    if (secretDisplay && secretDisplay.value) {
      navigator.clipboard.writeText(secretDisplay.value).then(() => {
        CREDTRACE.showToast("Secret Copied", "Synthetic API secret copied to clipboard! Ready to paste into Simulator.", "success");
      });
    }
  });

  document.getElementById("btn-generate-fresh-token")?.addEventListener("click", async () => {
    const room = CREDTRACE.getRoom();
    try {
      const resp = await fetch(`/api/portal/credential/generate-new?room=${encodeURIComponent(room)}`, {
        method: "POST"
      });
      const data = await resp.json();
      if (resp.ok && data.success) {
        if (secretDisplay) secretDisplay.value = data.synthetic_secret;
        if (credStatusBadge) {
          credStatusBadge.textContent = "ACTIVE (VALID)";
          credStatusBadge.className = "badge badge-low";
        }
        CREDTRACE.showToast("Token Reissued", "New synthetic secret generated and registered.", "success");
      }
    } catch (err) {
      console.error("Token generation error:", err);
    }
  });

  // 4. Support Tickets Handling
  async function loadTickets() {
    const room = CREDTRACE.getRoom();
    try {
      const resp = await fetch(`/api/portal/tickets?room=${encodeURIComponent(room)}`);
      if (resp.ok) {
        const tickets = await resp.json();
        renderTickets(tickets);
      }
    } catch (err) {
      console.error("Failed to fetch tickets:", err);
    }
  }

  function renderTickets(tickets) {
    if (!ticketsContainer) return;
    if (!tickets || tickets.length === 0) {
      ticketsContainer.innerHTML = `<div style="color:var(--text-dim); padding:16px;">No support tickets recorded.</div>`;
      return;
    }
    ticketsContainer.innerHTML = tickets.map(t => `
      <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:var(--radius-sm); padding:14px; margin-bottom:10px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
          <span style="font-weight:700; color:#fff; font-size:13px;">${t.ticket_id}: ${t.title}</span>
          <span class="badge ${t.status.includes('CLOSED') ? 'badge-low' : 'badge-high'}">${t.status}</span>
        </div>
        <div style="font-size:12px; color:var(--text-muted); margin-bottom:8px;">${t.description}</div>
        <div style="display:flex; justify-content:space-between; font-size:11px; color:var(--text-dim);">
          <span>Author: <b>${t.author}</b> | Category: ${t.category}</span>
          <span>Credential Associated: <b style="color:var(--accent-cyan);">${t.credential_id || 'None'}</b></span>
        </div>
      </div>
    `).join("");
  }

  // 5. Real-Time WebSocket Listeners
  CREDTRACE.on("containment", (msg) => {
    if (credStatusBadge) {
      credStatusBadge.textContent = "REVOKED (CONTAINED)";
      credStatusBadge.className = "badge badge-critical";
    }
  });

  CREDTRACE.on("reset", () => {
    loadCredential();
    loadTickets();
  });
});
