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

## What is implemented

- FastAPI + SQLite APIs for transactions, risk, IoT, devices, visitors, alerts, feedback, dashboard summary/timeline, and health.
- Isolation Forest anomaly detection and Random Forest known-fraud classification trained on generated synthetic data and persisted under `models/`.
- Transparent prototype risk fusion: fraud probability 25%, anomaly 20%, behaviour 15%, IP 10%, device 10%, location 10%, IoT tamper 10%. Decisions: ALLOW 0–39, REVIEW 40–69, BLOCK 70–100.
- Demo seed data: 120 transactions, 12 users, 5 terminals, suspicious patterns, alerts, and risk assessments.
- IoT geofence/tamper processing. Simulator emits realistic movement, heartbeat, vibration, offline, and tamper events.
- Dark SOC dashboard with risk charts, GPS-style live device map, visitors, alerts, transactions, and `/demo` presentation mode.
- `iot/esp8266/alphax_iot.ino` sends GPS + vibration JSON over HTTP. Set Wi-Fi, backend URL, device ID, and threshold at the top of the sketch.

## API examples

```bash
curl -X POST http://localhost:8000/api/iot/data -H 'content-type: application/json' -d '{"device_id":"ESP001","latitude":11.0168,"longitude":76.9558,"vibration":0.9,"online":true}'
curl -X POST http://localhost:8000/api/feedback -H 'content-type: application/json' -d '{"transaction_id":"TXN-1000","label":"TRUE_FRAUD","note":"Confirmed in review"}'
```

## Notes

This is a prototype using synthetic/demo data; the displayed evaluation metrics are calculated from a held-out synthetic dataset and are not real-world performance claims. Configure `DATABASE_URL`, `CORS_ORIGINS`, `VIBRATION_THRESHOLD`, and `GEOFENCE_KM` with environment variables if needed.
