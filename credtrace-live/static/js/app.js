/**
 * CREDTRACE V2 - Shared Real-Time Synchronization Engine
 * Manages Room partitioning, WebSocket persistence, auto-reconnection,
 * polling fallbacks, and multi-device event routing across the internet.
 */

const CREDTRACE = (function () {
  const DEFAULT_ROOM = "CR-26-047-DEMO";
  let activeRoom = DEFAULT_ROOM;
  let socket = null;
  let reconnectAttempts = 0;
  let pollingInterval = null;
  let lastEventId = 0;
  const listeners = {
    event: [],
    alert: [],
    containment: [],
    snapshot: [],
    reset: []
  };

  // 1. Initialize Room from URL or Storage
  function initRoom() {
    const urlParams = new URLSearchParams(window.location.search);
    const roomParam = urlParams.get("room");
    if (roomParam && roomParam.trim()) {
      activeRoom = roomParam.trim();
    } else {
      const stored = localStorage.getItem("credtrace_room");
      if (stored && stored.trim()) {
        activeRoom = stored.trim();
      }
    }
    localStorage.setItem("credtrace_room", activeRoom);

    // Sync input fields on page
    const inputs = document.querySelectorAll(".room-input");
    inputs.forEach(inp => {
      inp.value = activeRoom;
      inp.addEventListener("change", (e) => switchRoom(e.target.value));
    });

    const displayNodes = document.querySelectorAll(".current-room-id");
    displayNodes.forEach(n => n.textContent = activeRoom);
  }

  function switchRoom(newRoom) {
    if (!newRoom || !newRoom.trim()) return;
    activeRoom = newRoom.trim();
    localStorage.setItem("credtrace_room", activeRoom);
    
    // Update URL without reload
    const url = new URL(window.location);
    url.searchParams.set("room", activeRoom);
    window.history.replaceState({}, "", url);

    // Update displays
    document.querySelectorAll(".current-room-id").forEach(n => n.textContent = activeRoom);
    document.querySelectorAll(".room-input").forEach(inp => inp.value = activeRoom);

    // Reconnect socket
    connectWebSocket();
    showToast("Room Switched", `Connected to room: ${activeRoom}`, "info");
  }

  function getRoomShareUrl(targetModule = "") {
    const loc = window.location;
    const origin = loc.origin;
    const path = targetModule ? `/${targetModule}` : loc.pathname;
    return `${origin}${path}?room=${encodeURIComponent(activeRoom)}`;
  }

  function copyShareLink(targetModule = "") {
    const link = getRoomShareUrl(targetModule);
    navigator.clipboard.writeText(link).then(() => {
      showToast("Link Copied", `Copied shareable demo link for Laptop 2: ${link}`, "success");
    }).catch(err => {
      prompt("Copy this link to join on second laptop:", link);
    });
  }

  // 2. WebSocket Connection Management
  function connectWebSocket() {
    if (socket) {
      try { socket.close(); } catch (e) {}
    }

    updateConnectionStatus("reconnecting");

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws/events?room=${encodeURIComponent(activeRoom)}`;

    console.log(`[CREDTRACE] Connecting WebSocket to ${wsUrl}`);

    try {
      socket = new WebSocket(wsUrl);

      socket.onopen = function () {
        console.log(`[CREDTRACE] WebSocket Connected to room: ${activeRoom}`);
        reconnectAttempts = 0;
        updateConnectionStatus("connected");
        stopPollingFallback();
      };

      socket.onmessage = function (event) {
        try {
          const data = JSON.parse(event.data);
          handleIncomingMessage(data);
        } catch (e) {
          console.error("[CREDTRACE] Parse error on WS payload:", e);
        }
      };

      socket.onclose = function () {
        console.warn("[CREDTRACE] WebSocket Disconnected. Initiating recovery...");
        updateConnectionStatus("reconnecting");
        scheduleReconnect();
        startPollingFallback();
      };

      socket.onerror = function (err) {
        console.error("[CREDTRACE] WebSocket error observed:", err);
        socket.close();
      };
    } catch (err) {
      console.error("[CREDTRACE] Failed to instantiate WebSocket:", err);
      updateConnectionStatus("offline");
      startPollingFallback();
    }
  }

  function scheduleReconnect() {
    reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(1.5, reconnectAttempts), 8000);
    setTimeout(() => {
      if (!socket || socket.readyState === WebSocket.CLOSED) {
        connectWebSocket();
      }
    }, delay);
  }

  function updateConnectionStatus(state) {
    const pills = document.querySelectorAll(".ws-status-pill");
    pills.forEach(pill => {
      pill.className = `ws-status-pill ws-${state}`;
      const text = state === "connected" ? "LIVE SYNC" : state === "reconnecting" ? "RECONNECTING" : "OFFLINE";
      pill.innerHTML = `<span class="pulse-dot"></span> <span>${text}</span>`;
    });
  }

  // 3. Fallback Polling (When WS drops)
  function startPollingFallback() {
    if (pollingInterval) return;
    console.log("[CREDTRACE] Engaging HTTP telemetry polling fallback (3.5s interval)...");
    pollingInterval = setInterval(async () => {
      try {
        const resp = await fetch(`/api/investigator/events?room=${encodeURIComponent(activeRoom)}&limit=15&since_id=${lastEventId}`);
        if (resp.ok) {
          const events = await resp.json();
          if (events && events.length > 0) {
            events.forEach(evt => {
              if (evt.id > lastEventId) lastEventId = evt.id;
              listeners.event.forEach(cb => cb(evt));
            });
          }
        }
      } catch (err) {
        console.warn("[CREDTRACE] Polling check failed:", err);
      }
    }, 3500);
  }

  function stopPollingFallback() {
    if (pollingInterval) {
      clearInterval(pollingInterval);
      pollingInterval = null;
    }
  }

  // 4. Message Dispatcher
  function handleIncomingMessage(msg) {
    const type = msg.type;
    console.log("[CREDTRACE] Inbound Message:", type, msg);

    if (type === "INITIAL_SNAPSHOT") {
      if (msg.events && msg.events.length > 0) {
        const maxId = Math.max(...msg.events.map(e => e.id));
        if (maxId > lastEventId) lastEventId = maxId;
      }
      listeners.snapshot.forEach(cb => cb(msg));
    } else if (type === "NEW_SECURITY_EVENT") {
      if (msg.event && msg.event.id > lastEventId) lastEventId = msg.event.id;
      listeners.event.forEach(cb => cb(msg.event, msg.credential));
      if (msg.alerts && msg.alerts.length > 0) {
        msg.alerts.forEach(alt => {
          listeners.alert.forEach(cb => cb(alt));
          showToast(`THREAT ALERT [${alt.severity}]`, alt.rule_name, "critical");
        });
      }
    } else if (type === "CONTAINMENT_ENFORCED") {
      listeners.containment.forEach(cb => cb(msg));
      showToast("CONTAINMENT ENFORCED", `Credential ${msg.credential_id} was REVOKED by investigator!`, "critical");
    } else if (type === "ROOM_RESET") {
      lastEventId = 0;
      listeners.reset.forEach(cb => cb(msg));
      showToast("ROOM RESET", "Simulation room state was reset to clean baseline.", "info");
    }
  }

  function addListener(eventCategory, callback) {
    if (listeners[eventCategory]) {
      listeners[eventCategory].push(callback);
    }
  }

  // 5. Toast Notification System
  function showToast(title, message, variant = "info") {
    let container = document.getElementById("toast-container");
    if (!container) {
      container = document.createElement("div");
      container.id = "toast-container";
      document.body.appendChild(container);
    }

    const toast = document.createElement("div");
    toast.className = `toast ${variant === "critical" ? "toast-critical" : ""}`;
    toast.innerHTML = `
      <div>
        <div style="font-weight:700; font-size:12px; margin-bottom:2px;">${title}</div>
        <div style="font-size:11px; color:#cbd5e1;">${message}</div>
      </div>
    `;

    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(100%)";
      toast.style.transition = "all 0.3s ease";
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  }

  return {
    init: function () {
      initRoom();
      connectWebSocket();
    },
    getRoom: () => activeRoom,
    switchRoom: switchRoom,
    copyShareLink: copyShareLink,
    getRoomShareUrl: getRoomShareUrl,
    on: addListener,
    showToast: showToast
  };
})();

// Bootstrap on DOM ready
document.addEventListener("DOMContentLoaded", () => {
  CREDTRACE.init();
});
