import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ["DATABASE_URL"] = "sqlite:///./test_alphax.db"
os.environ["TRANSACTION_LIMIT"] = "100000"

from fastapi.testclient import TestClient

from app.config import settings
from app.database import SessionLocal
from app.main import app
from app.models import Alert, WebVisitor

client = TestClient(app)

def test_visitor_deduplication_and_privacy():
    headers = {"user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604.1", "x-forwarded-for": "198.51.100.30"}
    payload = {"visitor_id": "TEST-VISITOR", "device_name": "iPhone", "device_type": "Mobile", "os_hint": "iOS", "browser_version": "17"}
    first = client.post("/api/visitor/heartbeat", json=payload, headers=headers)
    second = client.post("/api/visitor/heartbeat", json=payload, headers=headers)
    assert first.status_code == second.status_code == 200
    assert first.json()["visitor_id"] == second.json()["visitor_id"]
    with SessionLocal() as db:
        assert db.query(WebVisitor).filter_by(visitor_id="TEST-VISITOR").count() == 1
        assert db.query(Alert).filter_by(title="ONLINE VISITOR").count() == 1
    assert "ip_address" not in client.get("/api/live-visitors").json()[0]
    assert client.get("/api/admin/live-visitors").json()[0]["ip_address"] == "198.51.100.30"

def test_visitor_expiry_and_transactions():
    settings.visitor_inactivity_seconds = 30
    with SessionLocal() as db:
        visitor = db.get(WebVisitor, "TEST-VISITOR")
        visitor.last_seen = datetime.now(timezone.utc) - timedelta(seconds=31)
        db.commit()
    assert client.get("/api/online-visitors").status_code == 200
    assert all(v["visitor_id"] != "TEST-VISITOR" for v in client.get("/api/online-visitors").json())
    normal = client.post("/api/transactions/analyze", json={"amount": 50000}).json()
    high = client.post("/api/transactions/analyze", json={"amount": 150000}).json()
    assert (normal["status"], normal["decision"], normal["alert"]) == ("NORMAL", "ALLOW", False)
    assert (high["status"], high["decision"], high["alert"]) == ("HIGH_RISK", "REVIEW", True)

def test_iot_regression():
    payload = {"device_id": "ESP001", "latitude": 11.013671, "longitude": 77.045553, "vibration": 0, "tamper_detected": False, "online": True}
    assert client.post("/api/iot/data", json=payload).status_code == 200
    assert any(d["id"] == "ESP001" for d in client.get("/api/iot/devices").json())
    assert any(v["visitor_type"] == "IOT" for v in client.get("/api/live-visitors").json())

def test_individual_tracking_endpoint():
    response=client.get("/api/admin/live-visitors/TEST-VISITOR")
    assert response.status_code == 200
    assert response.json()["visitor_id"] == "TEST-VISITOR"
    assert response.json()["ip_address"] == "198.51.100.30"
    assert client.get("/api/admin/live-visitors/does-not-exist").status_code == 404
