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
    normal = client.post("/api/transactions/analyze", json={"amount": 50000, "visitor_id":"TEST-VISITOR"}).json()
    high = client.post("/api/transactions/analyze", json={"amount": 150000, "visitor_id":"TEST-VISITOR"}).json()
    assert (normal["status"], normal["decision"], normal["alert"]) == ("NORMAL", "ALLOW", False)
    assert (high["status"], high["decision"], high["alert"]) == ("HIGH_RISK", "REVIEW", True)

def test_gps_heartbeat_updates_one_visitor_and_live_api():
    headers = {"user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604.1"}
    first = {"visitor_id": "GPS-VISITOR", "latitude": 11.013671, "longitude": 77.045553, "location_accuracy": 8.0, "location_source": "GPS"}
    second = {**first, "latitude": 11.0137, "longitude": 77.0456, "location_accuracy": 6.5}
    assert client.post("/api/visitor/heartbeat", json=first, headers=headers).json()["location_source"] == "GPS"
    response = client.post("/api/visitor/heartbeat", json=second, headers=headers)
    assert response.status_code == 200
    assert response.json()["latitude"] == second["latitude"]
    assert response.json()["longitude"] == second["longitude"]
    assert response.json()["location_accuracy"] == second["location_accuracy"]
    live = client.get("/api/admin/live-visitors").json()
    visitor = next(item for item in live if item["visitor_id"] == "GPS-VISITOR")
    assert visitor["latitude"] == second["latitude"]
    assert visitor["longitude"] == second["longitude"]
    assert visitor["location_source"] == "GPS"
    with SessionLocal() as db:
        assert db.query(WebVisitor).filter_by(visitor_id="GPS-VISITOR").count() == 1

def test_iot_regression():
    payload = {"device_id": "ESP001", "latitude": 11.013671, "longitude": 77.045553, "vibration": 0, "tamper_detected": False, "online": True}
    assert client.post("/api/iot/data", json=payload).status_code == 200
    assert any(d["id"] == "ESP001" for d in client.get("/api/iot/devices").json())
    assert any(v["visitor_type"] == "IOT" for v in client.get("/api/live-visitors").json())

def test_transactions_are_attributed_to_visitor():
    response=client.post("/api/transactions/analyze",json={"amount":150000,"visitor_id":"TEST-VISITOR"})
    assert response.status_code == 200
    body=response.json()
    assert body["actor"]["visitor_id"] == "TEST-VISITOR"
    assert body["actor"]["ip"] == "198.51.100.30"
    assert client.get("/api/admin/visitors/TEST-VISITOR/transactions").status_code == 200
    assert client.post("/api/transactions/analyze",json={"amount":150000}).status_code == 400

def test_individual_tracking_endpoint():
    response=client.get("/api/admin/live-visitors/TEST-VISITOR")
    assert response.status_code == 200
    assert response.json()["visitor_id"] == "TEST-VISITOR"
    assert response.json()["ip_address"] == "198.51.100.30"
    assert client.get("/api/admin/live-visitors/does-not-exist").status_code == 404

def test_phone_gps_updates_same_visitor_and_admin_api():
    headers = {"user-agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Version/17 Safari/604.1", "x-forwarded-for": "198.51.100.32"}
    first = {"visitor_id": "GPS-REGRESSION", "latitude": 11.013671, "longitude": 77.045553, "location_accuracy": 8.2, "location_source": "GPS", "device_name": "iPhone", "device_type": "Mobile", "os_hint": "iOS"}
    second = {**first, "latitude": 11.013721, "longitude": 77.045592}
    assert client.post("/api/visitor/heartbeat", json=first, headers=headers).status_code == 200
    assert client.post("/api/visitor/heartbeat", json=second, headers=headers).status_code == 200
    with SessionLocal() as db:
        assert db.query(WebVisitor).filter_by(visitor_id="GPS-REGRESSION").count() == 1
    item = next(v for v in client.get("/api/admin/live-visitors").json() if v["visitor_id"] == "GPS-REGRESSION")
    assert (item["latitude"], item["longitude"], item["location_source"], item["location_accuracy"]) == (11.013721, 77.045592, "GPS", 8.2)
