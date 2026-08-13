from datetime import datetime, timezone, timedelta
from pathlib import Path
import random, math
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, inspect, text
from .config import settings
from .database import Base, engine, get_db
from .models import User, Device, Transaction, IoTReading, RiskAssessment, Alert, AnalystFeedback
from .ml_engine import MLEngine
from .risk import assess, distance_km

Base.metadata.create_all(bind=engine)
# Keep existing SQLite/Render databases compatible when the device type column is
# added after the first deployment. This is intentionally idempotent.
if "device_type" not in {column["name"] for column in inspect(engine).get_columns("devices")}:
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE devices ADD COLUMN device_type VARCHAR"))
ml=MLEngine(settings.model_dir)
app=FastAPI(title="AlphaX-IoT Fraud Intelligence API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins.split(","), allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

class TxIn(BaseModel):
    user_id:str; amount:float=Field(gt=0); merchant:str; ip_address:str; device_id:str; latitude:float; longitude:float; transaction_velocity:float=Field(default=1,ge=0)
class IoTIn(BaseModel):
    device_id:str; latitude:float; longitude:float; vibration:float=Field(ge=0); timestamp:datetime|None=None; online:bool=True
    tamper_detected:bool|None=None
class FeedbackIn(BaseModel):
    transaction_id:str; label:str; note:str=""

def ser(obj):
    d={c.name:getattr(obj,c.name) for c in obj.__table__.columns}
    for k,v in d.items():
        if isinstance(v,datetime): d[k]=v.isoformat()
    return d
def tx_json(tx, risk=None):
    d=ser(tx); d["risk_score"]=round(risk.final_risk_score,1) if risk else 0; d["decision"]=risk.decision if risk else tx.status; return d
def user_ctx(db,user_id):
    u=db.get(User,user_id); ts=db.query(Transaction).filter(Transaction.user_id==user_id).order_by(desc(Transaction.timestamp)).all()
    return {"baseline":u.baseline_spend if u else 100,"devices":[t.device_id for t in ts[:8]],"last_lat":ts[0].latitude if ts else 11.0168,"last_lon":ts[0].longitude if ts else 76.9558}
def evaluate(db,tx):
    dev=db.get(Device,tx.device_id); r=assess(tx,user_ctx(db,tx.user_id),dev,ml); db.add(RiskAssessment(transaction_id=tx.id,**r)); tx.status=r["decision"]
    if r["decision"] in ("REVIEW","BLOCK"): db.add(Alert(severity="critical" if r["decision"]=="BLOCK" else "warning",title="HIGH RISK TRANSACTION",message=f"{tx.id} scored {r['final_risk_score']:.0f}. Decision: {r['decision']}",transaction_id=tx.id,device_id=tx.device_id))
    db.commit(); return r

@app.get("/api/health")
def health(): return {"status":"ok","service":"alphax-iot","ml":"isolation-forest + random-forest","mode":"demo-ready"}
@app.post("/api/transactions")
def create_tx(payload:TxIn,db:Session=Depends(get_db)):
    if not db.get(User,payload.user_id): raise HTTPException(404,"Unknown user")
    if not db.get(Device,payload.device_id): raise HTTPException(404,"Unknown device")
    tx=Transaction(id=f"TXN-{random.randint(10000,99999)}",timestamp=datetime.now(timezone.utc),**payload.model_dump()); db.add(tx); db.commit(); db.refresh(tx); r=evaluate(db,tx); return tx_json(tx,db.query(RiskAssessment).filter_by(transaction_id=tx.id).first())
@app.get("/api/transactions")
def transactions(limit:int=50,db:Session=Depends(get_db)):
    rows=[]
    for t in db.query(Transaction).order_by(desc(Transaction.timestamp)).limit(limit): rows.append(tx_json(t,db.query(RiskAssessment).filter_by(transaction_id=t.id).first()))
    return rows
@app.get("/api/transactions/{id}")
def transaction(id:str,db:Session=Depends(get_db)):
    t=db.get(Transaction,id); r=db.query(RiskAssessment).filter_by(transaction_id=id).first()
    if not t: raise HTTPException(404,"Transaction not found")
    return {"transaction":tx_json(t,r),"risk":ser(r) if r else None,"user":ser(db.get(User,t.user_id)),"device":ser(db.get(Device,t.device_id))}
@app.get("/api/risk/{transaction_id}")
def risk(transaction_id:str,db:Session=Depends(get_db)):
    r=db.query(RiskAssessment).filter_by(transaction_id=transaction_id).first(); return ser(r) if r else {"detail":"not found"}
@app.post("/api/iot/data")
def iot(payload:IoTIn,db:Session=Depends(get_db)):
    d=db.get(Device,payload.device_id)
    tamper=payload.vibration>settings.vibration_threshold or payload.tamper_detected is True
    reading_time=payload.timestamp or datetime.now(timezone.utc)
    if not d:
        d=Device(id=payload.device_id,name=f"{payload.device_id} IoT Device",device_type="ESP8266" if payload.device_id=="ESP001" else "IoT Device",expected_latitude=payload.latitude,expected_longitude=payload.longitude,latitude=payload.latitude,longitude=payload.longitude,vibration=payload.vibration,tamper_detected=tamper,online=payload.online,last_seen=reading_time,risk_score=90 if tamper else 15)
        db.add(d); db.flush()
    elif not d.device_type:
        d.device_type="ESP8266" if payload.device_id=="ESP001" else "IoT Device"
    moved=distance_km(d.expected_latitude,d.expected_longitude,payload.latitude,payload.longitude)>settings.geofence_km
    d.latitude=payload.latitude; d.longitude=payload.longitude; d.vibration=payload.vibration; d.tamper_detected=tamper; d.online=payload.online; d.last_seen=reading_time; d.risk_score=90 if tamper or moved else 15
    db.add(IoTReading(device_id=d.id,latitude=payload.latitude,longitude=payload.longitude,vibration=payload.vibration,tamper_detected=tamper,online=payload.online,timestamp=d.last_seen))
    if tamper: db.add(Alert(severity="critical",title="IOT TAMPER DETECTED",message=f"{d.id}: vibration {payload.vibration:.2f}",device_id=d.id))
    if moved: db.add(Alert(severity="critical",title="GEOFENCE BREACH",message=f"{d.id}: unexpected GPS movement",device_id=d.id))
    db.commit(); return {"device":ser(d),"tamper_detected":tamper,"location_anomaly":moved}
@app.get("/api/iot/devices")
def devices(db:Session=Depends(get_db)): return [ser(x) for x in db.query(Device).all()]
@app.get("/api/iot/devices/{id}")
def device(id:str,db:Session=Depends(get_db)):
    d=db.get(Device,id)
    if not d: raise HTTPException(404,"Device not found")
    return {"device":ser(d),"readings":[ser(x) for x in db.query(IoTReading).filter_by(device_id=id).order_by(desc(IoTReading.timestamp)).limit(30)]}
@app.get("/api/live-visitors")
def visitors(db:Session=Depends(get_db)): return [ser(x) for x in db.query(Device).order_by(desc(Device.last_seen)).all()]
@app.get("/api/location-data")
def locations(db:Session=Depends(get_db)): return [{"device_id":x.id,"latitude":x.latitude,"longitude":x.longitude,"risk_score":x.risk_score,"tamper":x.tamper_detected,"online":x.online,"last_seen":x.last_seen.isoformat()} for x in db.query(Device).all()]
@app.get("/api/alerts")
def alerts(db:Session=Depends(get_db)): return [ser(x) for x in db.query(Alert).filter_by(resolved=False).order_by(desc(Alert.created_at)).limit(30)]
@app.post("/api/alerts/{id}/resolve")
def resolve(id:int,db:Session=Depends(get_db)):
    a=db.get(Alert,id)
    if not a: raise HTTPException(404,"Alert not found")
    a.resolved=True; db.commit(); return ser(a)
@app.post("/api/feedback")
def feedback(payload:FeedbackIn,db:Session=Depends(get_db)):
    if payload.label not in ("TRUE_FRAUD","FALSE_POSITIVE","UNCERTAIN"): raise HTTPException(400,"Invalid label")
    f=AnalystFeedback(**payload.model_dump()); db.add(f); db.commit(); return ser(f)
@app.get("/api/dashboard/summary")
def summary(db:Session=Depends(get_db)):
    total=db.query(func.count(Transaction.id)).scalar(); high=db.query(func.count(Transaction.id)).filter(Transaction.status.in_(["REVIEW","BLOCK"])).scalar(); fraud=db.query(func.count(Transaction.id)).filter_by(status="BLOCK").scalar(); active=db.query(func.count(Device.id)).filter_by(online=True).scalar(); tamper=db.query(func.count(Alert.id)).filter(Alert.title.in_(["IOT TAMPER DETECTED","GEOFENCE BREACH"]),Alert.resolved==False).scalar(); fb=db.query(AnalystFeedback.label,func.count(AnalystFeedback.id)).group_by(AnalystFeedback.label).all()
    return {"total_transactions":total,"high_risk_transactions":high,"fraud_detected":fraud,"active_iot_devices":active,"live_visitors":active,"tamper_alerts":tamper,"feedback":dict(fb),"ml_metrics":ml.metrics()}
@app.get("/api/dashboard/timeline")
def timeline(db:Session=Depends(get_db)):
    rows=db.query(Transaction).order_by(Transaction.timestamp).limit(100).all(); return [{"time":t.timestamp.strftime("%H:%M"),"risk":round((db.query(RiskAssessment).filter_by(transaction_id=t.id).first().final_risk_score if db.query(RiskAssessment).filter_by(transaction_id=t.id).first() else 0),1)} for t in rows]
@app.get("/api/demo/state")
def demo_state(): return {"steps":[{"label":"Normal payment","detail":"Baseline transaction accepted","icon":"✓"},{"label":"New device","detail":"Device novelty increases risk","icon":"⌁"},{"label":"GPS anomaly","detail":"Terminal leaves geofence","icon":"⌖"},{"label":"Tamper spike","detail":"Vibration sensor triggers","icon":"⚠"},{"label":"Block decision","detail":"Cyber-physical risk fusion blocks payment","icon":"■"}]}
