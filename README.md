# AlphaX-IoT — Adaptive Real-Time Fraud & Cyber-Physical Intelligence

Demo-ready prototype fusing transaction intelligence with live GPS and vibration telemetry. It works without hardware through a simulator and includes a guided presentation route at `/demo`.

## Run locally

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python ../scripts/seed_demo_data.py
uvicorn app.main:app --reload --port 8000
```

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`, then open `/demo` for the controlled scenario. In a third terminal, run `python scripts/simulate_iot.py` for changing device telemetry. Swagger is at `http://localhost:8000/docs`.

## Deployment

For the current deployment, set the Vercel project environment variable `VITE_API_URL` to `https://alphax-backend-dexi.onrender.com`, then redeploy the frontend. The frontend also defaults to that Render URL when the variable is absent. Set Render `CORS_ORIGINS` to `https://alphax-iot.vercel.app,http://localhost:5173`. The included `render.yaml` documents the backend service configuration. After deploying a backend change, use `/api/health` and `/docs` on the Render URL to verify it is live.

## What is implemented

- FastAPI + SQLite APIs for transactions, risk, IoT, devices, visitors, alerts, feedback, dashboard summary/timeline, and health.
- Isolation Forest anomaly detection and Random Forest known-fraud classification trained on generated synthetic data and persisted under `models/`.
- Transparent prototype risk fusion: fraud probability 25%, anomaly 20%, behaviour 15%, IP 10%, device 10%, location 10%, IoT tamper 10%. Decisions: ALLOW 0–39, REVIEW 40–69, BLOCK 70–100.
- Demo seed data: 120 transactions, 12 users, 5 terminals, suspicious patterns, alerts, and risk assessments.
- IoT geofence/tamper processing. Simulator emits realistic movement, heartbeat, vibration, offline, and tamper events.
- Anonymous web visitor monitoring: browser-generated visitor ID, Render forwarded-IP enrichment, user-agent parsing, optional approximate IP geolocation, 20-second heartbeat, inactivity expiry, and unified IoT/ONLINE visitor feeds. Raw IP and user-agent are never returned by public visitor APIs.
- Dark SOC dashboard with risk charts, GPS-style live device map, visitors, alerts, transactions, and `/demo` presentation mode.
- `iot/esp8266/alphax_iot.ino` sends GPS + vibration JSON over HTTP. Set Wi-Fi, backend URL, device ID, and threshold at the top of the sketch.

## API examples

```bash
curl -X POST http://localhost:8000/api/iot/data -H 'content-type: application/json' -d '{"device_id":"ESP001","latitude":11.0168,"longitude":76.9558,"vibration":0.9,"online":true}'
curl -X POST http://localhost:8000/api/feedback -H 'content-type: application/json' -d '{"transaction_id":"TXN-1000","label":"TRUE_FRAUD","note":"Confirmed in review"}'
```

## Notes

This is a prototype using synthetic/demo data; the displayed evaluation metrics are calculated from a held-out synthetic dataset and are not real-world performance claims. Configure `DATABASE_URL`, `CORS_ORIGINS`, `VIBRATION_THRESHOLD`, and `GEOFENCE_KM` with environment variables if needed.

### Production visitor configuration

Keep the Vercel build variable set to:

```text
VITE_API_URL=https://alphax-backend-dexi.onrender.com
```

Keep Render CORS configured with:

```text
CORS_ORIGINS=https://alphax-iot.vercel.app,http://localhost:5173
TRANSACTION_LIMIT=100000
```

Optional IP geolocation settings are:

```text
IP_GEOLOCATION_URL=https://your-provider.example/lookup/{ip}
IP_GEOLOCATION_API_KEY=provider-key-if-required
VISITOR_INACTIVITY_SECONDS=30
TRUST_PROXY_HEADERS=true
TRANSACTION_LIMIT=100000
```

The provider URL must return JSON containing common fields such as `country_name`/`country`, `region`/`state_prov`, `city`, and `latitude`/`longitude` (or `lat`/`lon`). If it is unset or fails, the visitor remains tracked with `Unknown` approximate location. Browser exact GPS is not collected.

New APIs:

- `POST /api/visitor/heartbeat` — creates or refreshes an anonymous web visitor.
- `GET /api/online-visitors` — active web visitors only, with no raw IP.
- `GET /api/live-visitors` — unified IoT and ONLINE visitor response.
- `GET /api/location-data` — unified exact IoT and approximate web coordinates.
- `GET /api/admin/online-visitors` and `GET /api/admin/live-visitors` — dashboard/admin-shaped feeds that include stored IP addresses; add authentication before exposing these beyond the demo.
- `GET /api/admin/live-visitors/{visitor_id}` — latest individual web visitor detail or existing IoT device detail, returning 404 only when the ID does not exist.
- `POST /api/transactions/analyze` — analyzes a dashboard amount against the configured transaction limit and persists a risk assessment/alert.
- `GET /api/config/public` — exposes non-sensitive runtime thresholds to the dashboard.

The browser heartbeat runs every 5 seconds and dashboard polling runs every 2 seconds. A web visitor is marked offline after 30 seconds without a heartbeat. IoT locations remain exact device GPS; web locations are approximate IP geolocation only.

The frontend determines backend status only from `/api/health`; a successful 2xx health response keeps the system online even if a secondary dashboard endpoint fails. Dashboard refresh uses `Promise.allSettled()` and skips a new cycle while the prior cycle is still running. Vite production builds must set `VITE_API_URL=https://alphax-backend-dexi.onrender.com` and be redeployed after changing it.

For SQLite deployments, the backend uses `NullPool`, WAL mode, a busy timeout, and `check_same_thread=False`; this avoids QueuePool exhaustion during concurrent dashboard polling. If `DATABASE_URL` is PostgreSQL, the engine uses `pool_size=5`, `max_overflow=2`, `pool_timeout=10`, `pool_recycle=1800`, and `pool_pre_ping=True`. Request-scoped sessions are closed by `get_db()`; IP geolocation is performed before the database operation and cached per IP.
