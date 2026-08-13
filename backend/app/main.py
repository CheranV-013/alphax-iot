from datetime import datetime, timezone, timedelta
import json
from urllib.parse import quote
from urllib.request import Request as UrlRequest, urlopen
from pathlib import Path
import random, math
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, inspect, text
from .config import settings
from .database import Base, engine, get_db
from .models import User, Device, WebVisitor, Transaction, IoTReading, RiskAssessment, Alert, AnalystFeedback
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
class VisitorHeartbeatIn(BaseModel):
    visitor_id:str=Field(min_length=4,max_length=80,pattern=r"^[A-Za-z0-9_-]+$")
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

def utcnow():
    return datetime.now(timezone.utc)

def request_ip(request: Request):
    """Resolve the Render edge's forwarded address, with a socket fallback.

    Render supplies X-Forwarded-For at its trusted edge. We do not accept an
    IP in the JSON heartbeat body, and never return this value publicly.
    """
    if settings.trust_proxy_headers:
        forwarded=request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",",1)[0].strip()
    return request.client.host if request.client else "unknown"

def parse_user_agent(user_agent: str):
    ua=user_agent or ""
    if "Edg/" in ua: browser="Edge"
    elif "Chrome/" in ua and "Chromium" not in ua: browser="Chrome"
    elif "Firefox/" in ua: browser="Firefox"
    elif "Safari/" in ua and "Chrome/" not in ua: browser="Safari"
    elif "OPR/" in ua: browser="Opera"
    else: browser="Unknown"
    if "iPhone" in ua or "iPad" in ua: os="iOS"
    elif "Android" in ua: os="Android"
    elif "Mac OS X" in ua: os="macOS"
    elif "Windows" in ua: os="Windows"
    elif "Linux" in ua: os="Linux"
    else: os="Unknown"
    if "Mobile" in ua or "iPhone" in ua or "Android" in ua: device="Mobile"
    elif "iPad" in ua: device="Tablet"
    else: device="Desktop"
    return device,browser,os

def geo_for_ip(ip: str):
    unknown={"country":"Unknown","region":"Unknown","city":"Unknown","latitude":None,"longitude":None}
    url=settings.ip_geolocation_url.strip()
    if not url or ip in ("unknown","127.0.0.1","::1"):
        return unknown
    try:
        target=url.replace("{ip}",quote(ip,safe=""))
        headers={"User-Agent":"AlphaX-IoT visitor analytics"}
        if settings.ip_geolocation_api_key:
            target += ("&" if "?" in target else "?")+"apiKey="+quote(settings.ip_geolocation_api_key,safe="")
        with urlopen(UrlRequest(target,headers=headers),timeout=2) as response:
            data=json.loads(response.read().decode("utf-8"))
        return {"country":str(data.get("country_name") or data.get("country") or "Unknown"),"region":str(data.get("region") or data.get("state_prov") or "Unknown"),"city":str(data.get("city") or "Unknown"),"latitude":data.get("latitude",data.get("lat")),"longitude":data.get("longitude",data.get("lon"))}
    except Exception:
        return unknown

def mark_stale_visitors(db:Session):
    cutoff=utcnow()-timedelta(seconds=settings.visitor_inactivity_seconds)
    stale=db.query(WebVisitor).filter(WebVisitor.online.is_(True),WebVisitor.last_seen < cutoff).all()
    for visitor in stale:
        visitor.online=False
        db.add(Alert(severity="info",title="ONLINE VISITOR OFFLINE",message=f"Visitor {visitor.visitor_id} is no longer active"))
    if stale: db.commit()

def public_web_visitor(visitor:WebVisitor):
    return {"visitor_id":visitor.visitor_id,"visitor_type":"ONLINE","name":f"Visitor {visitor.visitor_id}","device_type":visitor.device_type,"browser":visitor.browser,"os":visitor.operating_system,"country":visitor.country,"region":visitor.region,"city":visitor.city,"latitude":visitor.latitude,"longitude":visitor.longitude,"online":visitor.online,"last_seen":visitor.last_seen.isoformat(),"first_seen":visitor.first_seen.isoformat()}

def public_iot_visitor(device:Device):
    return {"visitor_id":device.id,"id":device.id,"visitor_type":"IOT","name":device.name,"device_type":device.device_type or "IoT Device","latitude":device.latitude,"longitude":device.longitude,"online":device.online,"last_seen":device.last_seen.isoformat(),"vibration":device.vibration,"tamper_detected":device.tamper_detected,"risk_score":device.risk_score}
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

@app.post("/api/visitor/heartbeat")
def visitor_heartbeat(payload:VisitorHeartbeatIn, request:Request, db:Session=Depends(get_db)):
    now=utcnow(); existing=db.get(WebVisitor,payload.visitor_id); was_online=bool(existing and existing.online)
    user_agent=request.headers.get("user-agent","")
    device_type,browser,operating_system=parse_user_agent(user_agent)
    if not existing:
        geo=geo_for_ip(request_ip(request))
        existing=WebVisitor(visitor_id=payload.visitor_id,ip_address=request_ip(request),country=geo["country"],region=geo["region"],city=geo["city"],latitude=geo["latitude"],longitude=geo["longitude"],device_type=device_type,browser=browser,operating_system=operating_system,user_agent=user_agent,first_seen=now,last_seen=now,online=True)
        db.add(existing)
    else:
        existing.last_seen=now; existing.online=True; existing.device_type=device_type; existing.browser=browser; existing.operating_system=operating_system; existing.user_agent=user_agent
    if not was_online:
        db.add(Alert(severity="info",title="ONLINE VISITOR",message=f"Visitor {payload.visitor_id} connected"))
    db.commit(); db.refresh(existing)
    return public_web_visitor(existing)

@app.get("/api/online-visitors")
def online_visitors(db:Session=Depends(get_db)):
    mark_stale_visitors(db)
    return [public_web_visitor(v) for v in db.query(WebVisitor).filter_by(online=True).order_by(desc(WebVisitor.last_seen)).all()]

@app.get("/api/live-visitors")
def visitors(db:Session=Depends(get_db)):
    mark_stale_visitors(db)
    iot_visitors=[public_iot_visitor(x) for x in db.query(Device).order_by(desc(Device.last_seen)).all()]
    web_visitors=[public_web_visitor(x) for x in db.query(WebVisitor).filter_by(online=True).order_by(desc(WebVisitor.last_seen)).all()]
    return iot_visitors+web_visitors
@app.get("/api/location-data")
def locations(db:Session=Depends(get_db)):
    mark_stale_visitors(db)
    iot_locations=[{"device_id":x.id,"visitor_type":"IOT","latitude":x.latitude,"longitude":x.longitude,"risk_score":x.risk_score,"tamper":x.tamper_detected,"online":x.online,"last_seen":x.last_seen.isoformat()} for x in db.query(Device).all()]
    web_locations=[{"device_id":x.visitor_id,"visitor_type":"ONLINE","latitude":x.latitude,"longitude":x.longitude,"risk_score":None,"tamper":False,"online":x.online,"last_seen":x.last_seen.isoformat()} for x in db.query(WebVisitor).filter(WebVisitor.online.is_(True),WebVisitor.latitude.is_not(None),WebVisitor.longitude.is_not(None)).all()]
    return iot_locations+web_locations
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
    mark_stale_visitors(db)
    total=db.query(func.count(Transaction.id)).scalar(); high=db.query(func.count(Transaction.id)).filter(Transaction.status.in_(["REVIEW","BLOCK"])).scalar(); fraud=db.query(func.count(Transaction.id)).filter_by(status="BLOCK").scalar(); active_iot=db.query(func.count(Device.id)).filter_by(online=True).scalar(); active_web=db.query(func.count(WebVisitor.visitor_id)).filter_by(online=True).scalar(); tamper=db.query(func.count(Alert.id)).filter(Alert.title.in_(["IOT TAMPER DETECTED","GEOFENCE BREACH"]),Alert.resolved==False).scalar(); fb=db.query(AnalystFeedback.label,func.count(AnalystFeedback.id)).group_by(AnalystFeedback.label).all()
    return {"total_transactions":total,"high_risk_transactions":high,"fraud_detected":fraud,"active_iot_devices":active_iot,"live_visitors":active_iot+active_web,"live_visitors_iot":active_iot,"live_visitors_online":active_web,"tamper_alerts":tamper,"feedback":dict(fb),"ml_metrics":ml.metrics()}
@app.get("/api/dashboard/timeline")
def timeline(db:Session=Depends(get_db)):
    rows=db.query(Transaction).order_by(Transaction.timestamp).limit(100).all(); return [{"time":t.timestamp.strftime("%H:%M"),"risk":round((db.query(RiskAssessment).filter_by(transaction_id=t.id).first().final_risk_score if db.query(RiskAssessment).filter_by(transaction_id=t.id).first() else 0),1)} for t in rows]
@app.get("/api/demo/state")
def demo_state(): return {"steps":[{"label":"Normal payment","detail":"Baseline transaction accepted","icon":"✓"},{"label":"New device","detail":"Device novelty increases risk","icon":"⌁"},{"label":"GPS anomaly","detail":"Terminal leaves geofence","icon":"⌖"},{"label":"Tamper spike","detail":"Vibration sensor triggers","icon":"⚠"},{"label":"Block decision","detail":"Cyber-physical risk fusion blocks payment","icon":"■"}]}
