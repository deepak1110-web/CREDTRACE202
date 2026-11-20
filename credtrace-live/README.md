# CREDTRACE V2 – Real-Time Cybercrime Incident Simulation Platform
### CRIMEATHON'26 | Case CR-26-047: Harbor & Finch Freight Pvt. Ltd.

CREDTRACE V2 is an interactive digital forensics, credential intelligence, and cybercrime incident simulation platform engineered for multi-device internet operation across physically separate laptops.

---

## 🚀 Two-Device Live Demonstration Guide (For Judges)

The platform is designed for an end-to-end two-laptop workflow connected over the internet or a shared network via a synchronized **Room ID** (default: `CR-26-047-DEMO`).

```
+------------------------------------+        +------------------------------------+
|             LAPTOP 1               |        |             LAPTOP 2               |
|      INVESTIGATOR SOC DASHBOARD    | <====> |    COMPANY PORTAL & SIMULATOR      |
|  (/investigator?room=CR-26-047-DEMO) | (WSS)  |    (/simulator?room=CR-26-047-DEMO)|
+------------------------------------+        +------------------------------------+
                                         ^
                                         | (Live WebSocket Events & Shared DB)
                                         v
                         +-------------------------------+
                         |   CREDTRACE BACKEND SERVICE   |
                         |  (Render / Neon / FastAPIRoot)|
                         +-------------------------------+
```

### Exact Demonstration Steps:

1. **Laptop 1 (Investigator SOC)**:
   - Open `/investigator` in the browser.
   - Note the room ID (`CR-26-047-DEMO`) and the green **LIVE SYNC** badge.
   - Leave the Live Security Events Feed visible on screen.

2. **Laptop 2 (Company Portal)**:
   - Open `/portal` in the browser.
   - Click one-click login for **Sarah Chen (Operations Lead)**.
   - View Support Ticket **TKT-48213** where credential identifier **`bvk-7f3a`** was issued.
   - Click **COPY SECRET** to copy the generated synthetic secret (`sec_live_...`).

3. **Laptop 2 (Adversary Simulator)**:
   - Open `/simulator` in the browser.
   - Enter/paste the synthetic test secret and click **Authenticate Device**.
   - **Watch Laptop 1 instantly!** The `SIMULATOR_AUTH_SUCCESS` event appears in real time without refreshing.
   - Click **Enumerate Vendor APIs** and **Query Customer Manifests**. Telemetry streams to Laptop 1.

4. **Trigger Exfiltration & Real Threat Detection**:
   - On Laptop 2, click **Attempt Bulk Data Export**.
   - The backend access control policy intercepts the action with **HTTP 403 Forbidden**.
   - **Laptop 1 instantly triggers a Critical Alert**: `RULE-002-RESTRICTED-EXPORT` ("Restricted Bulk Data Export Attempt") and the Risk Score jumps on the visual gauge.

5. **Execute Live Server-Side Containment**:
   - On Laptop 1, the investigator clicks **&times; REVOKE BVK-7F3A** in the header.
   - The credential status changes to **REVOKED** in the database, and an audit event is chained.
   - **Laptop 2 instantly flashes a red containment banner**: `[CONTAINMENT ACTIVATED BY INVESTIGATOR]`.

6. **Verify Post-Revocation Enforcement**:
   - On Laptop 2, attempt to click **Query Customer Manifests** or **Authenticate Device** again.
   - The backend rejects the request with **HTTP 403 Forbidden** and logs `POST_REVOCATION_ATTEMPT`.
   - Laptop 1 displays the rejection in real time!

7. **Cryptographic Hash Chain Verification & Report**:
   - On Laptop 1, switch to the **Cryptographic Forensics** tab. Click **Verify Hash Chain**.
   - The system validates the SHA-256 hash linkage from the Genesis block across all events: **CHAIN INTACT & VALID**.
   - Click **Forensic Reports Export** and click **DOWNLOAD FORENSIC PDF** to inspect the official generated ReportLab case record.

---

## ⚡ 3-Minute Deployment Guide on Render

The backend is configured as a single unified service that serves the FastAPI backend, WebSocket broker, and all front-end interfaces simultaneously.

### Step 1: Push to GitHub
```bash
git init
git add .
git commit -m "CREDTRACE V2 Hackathon Build"
git remote add origin https://github.com/YOUR_USERNAME/credtrace.git
git branch -M main
git push -u origin main
```

### Step 2: Deploy on Render
1. Log into your [Render Dashboard](https://dashboard.render.com).
2. Click **New +** &rarr; **Web Service**.
3. Select your `credtrace` GitHub repository.
4. Render will automatically detect the settings from `render.yaml`:
   - **Environment**: Python
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. *(Optional for PostgreSQL)* Add Environment Variable:
   - `DATABASE_URL`: Your Neon or Render PostgreSQL connection string (e.g. `postgresql://...`).
   *(If omitted, CREDTRACE automatically uses persistent SQLite with zero setup!)*
6. Click **Deploy Web Service**.

Once deployed, Render gives you a public HTTPS URL (e.g., `https://credtrace-live.onrender.com`).
Both laptops can immediately access the URL over the internet!

---

## 🧪 Local Testing & Verification

CREDTRACE includes automated test suites covering all 18 requirements:

```bash
# Run core cryptographic, correlation, and database engine tests:
python run_tests.py

# Run live end-to-end HTTP endpoint and socket integration tests:
python tests/test_live_api.py
```

### Automated Acceptance Checks Passed:
- [x] Health probe (`/health`, `/api/status`)
- [x] Company portal authentication (`/api/login`, fixes 404)
- [x] Demo identities for one-click judge login
- [x] Credential exposure (`bvk-7f3a`, separate random synthetic secret)
- [x] Support ticket generation (`TKT-48213`)
- [x] Controlled adversary authentication & session tracking
- [x] Synthetic customer & vendor manifest querying
- [x] Restricted bulk data export policy interception (HTTP 403)
- [x] Real rule-based threat detection engine & risk scoring (0-100)
- [x] Explainable multi-source technical correlation matrix
- [x] Server-side credential containment and instant revocation
- [x] Post-revocation rejection on adversary client (HTTP 403)
- [x] Cryptographic SHA-256 hash chaining & tamper-evident verification
- [x] ReportLab forensic PDF generation & JSON data export
- [x] Room state reset for clean demonstration cycles

---

## 🛡️ Forensic Boundaries & Evidence Limitations

1. **Synthetic Secret Model**: Credential identifier `bvk-7f3a` is an indexing handle; the backend securely stores only a salted SHA-256 hash. Production root secrets were never accessed or exposed.
2. **Network Attribution**: IP addresses represent packet routing paths, not legal human identities.
3. **Cryptographic Proofs**: SHA-256 hash chaining proves sequence integrity against modification, deletion, or reordering of event records.
