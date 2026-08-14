from datetime import datetime, timezone, timedelta
import json
import ipaddress
import threading
from urllib.parse import quote
from urllib.request import Request as UrlRequest, urlopen
from pathlib import Path
import random, math
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, inspect, text
from sqlalchemy.exc import IntegrityError, OperationalError
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
web_visitor_columns={column["name"] for column in inspect(engine).get_columns("web_visitors")}
with engine.begin() as connection:
    if "device_name" not in web_visitor_columns: connection.execute(text("ALTER TABLE web_visitors ADD COLUMN device_name VARCHAR DEFAULT 'Unknown'"))
    if "browser_version" not in web_visitor_columns: connection.execute(text("ALTER TABLE web_visitors ADD COLUMN browser_version VARCHAR DEFAULT 'Unknown'"))
    if "location_accuracy" not in web_visitor_columns: connection.execute(text("ALTER TABLE web_visitors ADD COLUMN location_accuracy FLOAT"))
    if "location_source" not in web_visitor_columns: connection.execute(text("ALTER TABLE web_visitors ADD COLUMN location_source VARCHAR DEFAULT 'UNKNOWN'"))
transaction_columns={column["name"] for column in inspect(engine).get_columns("transactions")}
with engine.begin() as connection:
    additions={"visitor_id":"VARCHAR","browser":"VARCHAR","operating_system":"VARCHAR","device_type":"VARCHAR","location_accuracy":"FLOAT","location_source":"VARCHAR"}
    for name,sql_type in additions.items():
        if name not in transaction_columns: connection.execute(text(f"ALTER TABLE transactions ADD COLUMN {name} {sql_type}"))
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
    device_name:str|None=None
    browser_version:str|None=None
    device_type:str|None=None
    os_hint:str|None=None
    latitude:float|None=None
    longitude:float|None=None
    location_accuracy:float|None=Field(default=None,ge=0)
    location_source:str|None=None
class FeedbackIn(BaseModel):
    transaction_id:str; label:str; note:str=""
class AnalyzeTransactionIn(BaseModel):
    amount:float=Field(gt=0)
    user_id:str|None=None
    device_id:str|None=None
    ip_address:str="0.0.0.0"
    latitude:float=0
    longitude:float=0
    transaction_velocity:float=Field(default=1,ge=0)
    visitor_id:str|None=None
    device_id:str|None=None

def ser(obj):
    d={c.name:getattr(obj,c.name) for c in obj.__table__.columns}
    for k,v in d.items():
        if isinstance(v,datetime): d[k]=iso_timestamp(v)
    return d
def iso_timestamp(value:datetime):
    aware=value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return aware.astimezone(timezone.utc).isoformat().replace('+00:00','Z')
def tx_json(tx, risk=None):
    d=ser(tx); d["risk_score"]=round(risk.final_risk_score,1) if risk else 0; d["decision"]=risk.decision if risk else tx.status; return d
def user_ctx(db,user_id):
    u=db.get(User,user_id) if user_id else None; ts=db.query(Transaction).filter(Transaction.user_id==user_id).order_by(desc(Transaction.timestamp)).all() if user_id else []
    return {"baseline":u.baseline_spend if u else 100,"devices":[t.device_id for t in ts[:8]],"last_lat":ts[0].latitude if ts else 11.0168,"last_lon":ts[0].longitude if ts else 76.9558}
def transaction_actor(db:Session, tx:Transaction):
    if tx.visitor_id:
        visitor=db.get(WebVisitor,tx.visitor_id)
        if visitor:
            return {"visitor_id":visitor.visitor_id,"device":visitor.device_name or visitor.device_type,"browser":visitor.browser,"os":visitor.operating_system,"ip":visitor.ip_address,"device_type":visitor.device_type,"online":visitor.online,"last_seen":iso_timestamp(visitor.last_seen),"location":{"source":visitor.location_source,"latitude":visitor.latitude,"longitude":visitor.longitude,"accuracy":visitor.location_accuracy}}
    if tx.device_id:
        device=db.get(Device,tx.device_id)
        if device: return {"device_id":device.id,"device":device.name,"device_type":device.device_type,"online":device.online,"last_seen":iso_timestamp(device.last_seen),"location":{"source":"GPS","latitude":device.latitude,"longitude":device.longitude,"accuracy":None}}
    return None
def transaction_location(tx):
    return {"latitude":tx.latitude,"longitude":tx.longitude,"source":tx.location_source or "UNKNOWN","accuracy":tx.location_accuracy}

def current_actor_location(actor):
    return actor.get("location") if actor else None

def utcnow():
    return datetime.now(timezone.utc)

def _valid_ip(value: str | None):
    try:
        return str(ipaddress.ip_address(value.strip())) if value else None
    except (ValueError, AttributeError):
        return None

def get_client_ip(request: Request):
    """Resolve the client IP from Render's trusted proxy chain.

    The JSON heartbeat never accepts an IP. When proxy headers are enabled,
    use the documented edge headers in priority order and validate every
    candidate; otherwise fall back to the socket peer.
    """
    if settings.trust_proxy_headers:
        candidate=_valid_ip(request.headers.get("cf-connecting-ip"))
        if candidate: return candidate
        forwarded=request.headers.get("x-forwarded-for","")
        for value in forwarded.split(","):
            candidate=_valid_ip(value)
            if candidate: return candidate
        candidate=_valid_ip(request.headers.get("x-real-ip"))
        if candidate: return candidate
    return _valid_ip(request.client.host if request.client else None) or "unknown"

request_ip=get_client_ip

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
    version="Unknown"
    marker={"Edge":"Edg/","Chrome":"Chrome/","Firefox":"Firefox/","Safari":"Version/","Opera":"OPR/"}.get(browser)
    if marker and marker in ua: version=ua.split(marker,1)[1].split(".",1)[0]
    if "iPhone" in ua: device_name="iPhone"
    elif "iPad" in ua: device_name="iPad"
    elif "Android" in ua:
        fragment=ua.split("Android",1)[1].split(")",1)[0]
        candidates=[x.strip() for x in fragment.split(";")[1:]]
        device_name=next((x for x in candidates if x and x not in ("wv","Mobile")),"Unknown")
    else: device_name="Unknown"
    return device,browser,os,device_name,version

def geo_for_ip(ip: str):
    unknown={"country":"Unknown","region":"Unknown","city":"Unknown","latitude":None,"longitude":None}
    cached=_GEO_CACHE.get(ip)
    if cached: return cached.copy()
    url=settings.ip_geolocation_url.strip()
    if not url or ip in ("unknown","127.0.0.1","::1"):
        _GEO_CACHE[ip]=unknown.copy()
        return unknown
    try:
        target=url.replace("{ip}",quote(ip,safe=""))
        headers={"User-Agent":"AlphaX-IoT visitor analytics"}
        if settings.ip_geolocation_api_key:
            target += ("&" if "?" in target else "?")+"apiKey="+quote(settings.ip_geolocation_api_key,safe="")
        with urlopen(UrlRequest(target,headers=headers),timeout=2) as response:
            data=json.loads(response.read().decode("utf-8"))
        result={"country":str(data.get("country_name") or data.get("country") or "Unknown"),"region":str(data.get("region") or data.get("state_prov") or "Unknown"),"city":str(data.get("city") or "Unknown"),"latitude":data.get("latitude",data.get("lat")),"longitude":data.get("longitude",data.get("lon"))}
        _GEO_CACHE[ip]=result.copy(); return result
    except Exception:
        _GEO_CACHE[ip]=unknown.copy()
        return unknown

_GEO_CACHE={}

def mark_stale_visitors(db:Session):
    cutoff=utcnow()-timedelta(seconds=settings.visitor_inactivity_seconds)
    stale=db.query(WebVisitor).filter(WebVisitor.online.is_(True),WebVisitor.last_seen < cutoff).all()
    for visitor in stale:
        visitor.online=False
        db.add(Alert(severity="info",title="OFFLINE VISITOR",message=f"Visitor {visitor.visitor_id} is no longer active"))
    if stale: db.commit()

def public_web_visitor(visitor:WebVisitor, include_ip=False):
    result={"id":visitor.visitor_id,"visitor_id":visitor.visitor_id,"visitor_type":"ONLINE","name":f"Visitor {visitor.visitor_id}","device_type":visitor.device_type,"device_name":visitor.device_name,"browser":visitor.browser,"browser_version":visitor.browser_version,"os":visitor.operating_system,"operating_system":visitor.operating_system,"country":visitor.country,"region":visitor.region,"city":visitor.city,"latitude":visitor.latitude,"longitude":visitor.longitude,"location_accuracy":visitor.location_accuracy,"location_source":visitor.location_source,"online":visitor.online,"last_seen":iso_timestamp(visitor.last_seen),"first_seen":iso_timestamp(visitor.first_seen)}
    if include_ip: result["ip_address"]=visitor.ip_address
    return result

def public_iot_visitor(device:Device):
    return {"visitor_id":device.id,"id":device.id,"visitor_type":"IOT","name":device.name,"device_type":device.device_type or "IoT Device","latitude":device.latitude,"longitude":device.longitude,"online":device.online,"last_seen":iso_timestamp(device.last_seen),"vibration":device.vibration,"tamper_detected":device.tamper_detected,"risk_score":device.risk_score}
def evaluate(db,tx,model_amount=None):
    dev=db.get(Device,tx.device_id) if tx.device_id else None; r=assess(tx,user_ctx(db,tx.user_id),dev,ml,model_amount=model_amount); db.add(RiskAssessment(transaction_id=tx.id,**r)); tx.status=r["decision"]
    actor=transaction_actor(db,tx); actor_label=actor.get("visitor_id") if actor and actor.get("visitor_id") else actor.get("device_id") if actor else "Unknown actor"
    if tx.amount>=settings.transaction_limit:
        db.add(Alert(severity="critical" if r["decision"]=="BLOCK" else "warning",title="HIGH VALUE TRANSACTION",message=f"Amount: {tx.amount:.2f}. Actor: {actor_label}. Risk: {r['final_risk_score']:.0f}. Decision: {r['decision']}. Exceeds configured threshold {settings.transaction_limit:.2f}.",transaction_id=tx.id,device_id=tx.device_id))
    elif r["decision"] in ("REVIEW","BLOCK"):
        db.add(Alert(severity="critical" if r["decision"]=="BLOCK" else "warning",title="HIGH RISK TRANSACTION",message=f"{tx.id} scored {r['final_risk_score']:.0f}. Decision: {r['decision']}",transaction_id=tx.id,device_id=tx.device_id))
    db.commit(); return r

@app.get("/api/health")
def health(): return {"status":"ok","service":"alphax-iot","ml":"isolation-forest + random-forest","mode":"demo-ready"}
@app.get("/api/config/public")
def public_config(): return {"transaction_limit":settings.transaction_limit,"visitor_inactivity_seconds":settings.visitor_inactivity_seconds}
@app.post("/api/transactions")
def create_tx(payload:TxIn,db:Session=Depends(get_db)):
    if not db.get(User,payload.user_id): raise HTTPException(404,"Unknown user")
    if not db.get(Device,payload.device_id): raise HTTPException(404,"Unknown device")
    tx=Transaction(id=f"TXN-{random.randint(10000,99999)}",timestamp=datetime.now(timezone.utc),**payload.model_dump()); db.add(tx); db.commit(); db.refresh(tx); r=evaluate(db,tx); return tx_json(tx,db.query(RiskAssessment).filter_by(transaction_id=tx.id).first())
@app.post("/api/transactions/analyze")
def analyze_transaction(payload:AnalyzeTransactionIn,db:Session=Depends(get_db)):
    visitor=db.get(WebVisitor,payload.visitor_id) if payload.visitor_id else None
    device=db.get(Device,payload.device_id) if payload.device_id else None
    if payload.visitor_id and not visitor: raise HTTPException(404,"Unknown visitor actor")
    if payload.device_id and not device: raise HTTPException(404,"Unknown device actor")
    if not visitor and not device: raise HTTPException(400,"Select a transaction actor")
    now=utcnow(); recent_count=0
    if visitor: recent_count=db.query(func.count(Transaction.id)).filter(Transaction.visitor_id==visitor.visitor_id,Transaction.timestamp>=now-timedelta(minutes=10)).scalar() or 0
    actor_ip=visitor.ip_address if visitor else None
    actor_lat=visitor.latitude if visitor else device.latitude
    actor_lon=visitor.longitude if visitor else device.longitude
    actor_accuracy=visitor.location_accuracy if visitor else None
    actor_source=visitor.location_source if visitor else "GPS"
    actor_browser=visitor.browser if visitor else None
    actor_os=visitor.operating_system if visitor else None
    actor_type=visitor.device_type if visitor else device.device_type
    actor_device=visitor.device_name if visitor else device.id
    linked_user_id=payload.user_id or (f"VISITOR-{visitor.visitor_id}" if visitor else f"DEVICE-{device.id}")
    if not db.get(User,linked_user_id): db.add(User(id=linked_user_id,name=f"Anonymous actor {visitor.visitor_id if visitor else device.id}",email=f"{linked_user_id.lower()}@anonymous.local",baseline_spend=settings.transaction_limit)); db.flush()
    tx=Transaction(id=f"ANL-{random.randint(100000,999999)}",user_id=linked_user_id,visitor_id=visitor.visitor_id if visitor else None,amount=payload.amount,timestamp=now,merchant="Dashboard Transaction Monitor",ip_address=actor_ip,device_id=device.id if device else None,browser=actor_browser,operating_system=actor_os,device_type=actor_type,latitude=actor_lat,longitude=actor_lon,location_accuracy=actor_accuracy,location_source=actor_source,transaction_velocity=payload.transaction_velocity+recent_count,status="PENDING")
    db.add(tx); db.commit(); db.refresh(tx)
    normalized_model_amount=min((payload.amount/max(settings.transaction_limit,1))*500,500)
    r=evaluate(db,tx,model_amount=normalized_model_amount)
    assessment=db.query(RiskAssessment).filter_by(transaction_id=tx.id).first()
    high=payload.amount>=settings.transaction_limit
    if not high and r["decision"] != "ALLOW":
        # The dashboard monitor's configured business rule explicitly treats
        # below-limit checks as NORMAL/ALLOW; the full component scores remain
        # stored for later investigation.
        r["decision"]="ALLOW"; tx.status="ALLOW"
        if assessment: assessment.decision="ALLOW"
        db.commit()
    actor=transaction_actor(db,tx); location=transaction_location(tx)
    return {"transaction_id":tx.id,"amount":payload.amount,"threshold":settings.transaction_limit,"status":"HIGH_RISK" if high else "NORMAL","risk_score":round(r["final_risk_score"],1),"decision":r["decision"],"alert":high,"reason":"Transaction exceeds configured threshold." if high else "Below configured threshold.","actor":actor,"location":location,"risk":ser(assessment)}
@app.get("/api/transactions")
def transactions(limit:int=50,db:Session=Depends(get_db)):
    rows=[]
    for t in db.query(Transaction).order_by(desc(Transaction.timestamp)).limit(limit):
        item=tx_json(t,db.query(RiskAssessment).filter_by(transaction_id=t.id).first()); item["actor"]=transaction_actor(db,t); item["location"]=transaction_location(t); rows.append(item)
    return rows
@app.get("/api/admin/visitors/{visitor_id}/transactions")
def visitor_transactions(visitor_id:str,db:Session=Depends(get_db)):
    if not db.get(WebVisitor,visitor_id): raise HTTPException(404,"Visitor not found")
    return [{**tx_json(t,db.query(RiskAssessment).filter_by(transaction_id=t.id).first()),"actor":transaction_actor(db,t),"location":transaction_location(t)} for t in db.query(Transaction).filter(Transaction.visitor_id==visitor_id).order_by(desc(Transaction.timestamp)).all()]
@app.get("/api/admin/transactions/{transaction_id}")
def investigate_transaction(transaction_id:str,db:Session=Depends(get_db)):
    t=db.get(Transaction,transaction_id)
    if not t: raise HTTPException(404,"Transaction not found")
    risk=db.query(RiskAssessment).filter_by(transaction_id=t.id).first(); actor=transaction_actor(db,t); visitor=db.get(WebVisitor,t.visitor_id) if t.visitor_id else None
    live_location=current_actor_location(actor) or transaction_location(t)
    return {"transaction":tx_json(t,risk),"current_actor":actor,"actor":actor,"location":live_location,"last_visitor_activity":actor.get("last_seen") if actor else None,"risk":ser(risk) if risk else None,"visitor_history":[tx_json(x,db.query(RiskAssessment).filter_by(transaction_id=x.id).first()) for x in db.query(Transaction).filter(Transaction.visitor_id==t.visitor_id).order_by(desc(Transaction.timestamp)).all()] if t.visitor_id else []}
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
        db.add(d)
        try:
            db.flush()
        except IntegrityError:
            # Two ESP heartbeats can arrive at the same time on a fresh
            # deployment. The primary key is the registration lock: reuse the
            # winner instead of creating a duplicate or returning an error.
            db.rollback()
            d=db.get(Device,payload.device_id)
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
    now=utcnow(); current_ip=get_client_ip(request)
    user_agent=request.headers.get("user-agent","")
    device_type,browser,operating_system,parsed_device_name,parsed_browser_version=parse_user_agent(user_agent)
    device_type=payload.device_type or device_type; device_name=payload.device_name or parsed_device_name; browser_version=payload.browser_version or parsed_browser_version; operating_system=payload.os_hint or operating_system
    has_gps=payload.latitude is not None and payload.longitude is not None and payload.location_source == "GPS"
    # GPS is the primary location. Do not make a visitor heartbeat wait on an
    # external IP lookup when the browser has already supplied a fresh fix.
    geo=geo_for_ip(current_ip) if not has_gps else {"country":"Unknown","region":"Unknown","city":"Unknown","latitude":None,"longitude":None}
    existing=db.get(WebVisitor,payload.visitor_id); was_online=bool(existing and existing.online)
    if not existing:
        existing=WebVisitor(visitor_id=payload.visitor_id,ip_address=current_ip,country=geo["country"],region=geo["region"],city=geo["city"],latitude=payload.latitude if has_gps else geo["latitude"],longitude=payload.longitude if has_gps else geo["longitude"],location_accuracy=payload.location_accuracy if has_gps else None,location_source="GPS" if has_gps else ("IP" if geo["latitude"] is not None else "UNKNOWN"),device_type=device_type,device_name=device_name,browser=browser,browser_version=browser_version,operating_system=operating_system,user_agent=user_agent,first_seen=now,last_seen=now,online=True)
        db.add(existing)
    else:
        if existing.ip_address!=current_ip:
            existing.ip_address=current_ip; existing.country=geo["country"]; existing.region=geo["region"]; existing.city=geo["city"]
            if existing.location_source!="GPS": existing.latitude=geo["latitude"]; existing.longitude=geo["longitude"]
        if has_gps:
            existing.latitude=payload.latitude; existing.longitude=payload.longitude; existing.location_accuracy=payload.location_accuracy; existing.location_source="GPS"
        elif existing.location_source!="GPS":
            existing.latitude=geo["latitude"]; existing.longitude=geo["longitude"]; existing.location_accuracy=None; existing.location_source="IP" if geo["latitude"] is not None else "UNKNOWN"
        existing.last_seen=now; existing.online=True; existing.device_type=device_type; existing.device_name=device_name; existing.browser=browser; existing.browser_version=browser_version; existing.operating_system=operating_system; existing.user_agent=user_agent
    if not was_online:
        db.add(Alert(severity="info",title="ONLINE VISITOR",message=f"Visitor {payload.visitor_id} connected"))
    try:
        db.commit()
    except IntegrityError:
        # Concurrent first heartbeats for the same anonymous browser can race.
        # The unique visitor_id wins; retry as an update without duplicating an
        # online alert or visitor row.
        db.rollback()
        existing=db.get(WebVisitor,payload.visitor_id)
        if not existing: raise
        existing.ip_address=current_ip; existing.last_seen=now; existing.online=True; existing.device_type=device_type; existing.device_name=device_name; existing.browser=browser; existing.browser_version=browser_version; existing.operating_system=operating_system; existing.user_agent=user_agent
        if has_gps:
            existing.latitude=payload.latitude; existing.longitude=payload.longitude; existing.location_accuracy=payload.location_accuracy; existing.location_source="GPS"
        db.commit()
    db.refresh(existing)
    return public_web_visitor(existing)

@app.get("/api/online-visitors")
def online_visitors(db:Session=Depends(get_db)):
    mark_stale_visitors(db)
    return [public_web_visitor(v) for v in db.query(WebVisitor).filter_by(online=True).order_by(desc(WebVisitor.last_seen)).all()]

@app.get("/api/admin/online-visitors")
def admin_online_visitors(db:Session=Depends(get_db)):
    mark_stale_visitors(db)
    return [public_web_visitor(v,include_ip=True) for v in db.query(WebVisitor).filter_by(online=True).order_by(desc(WebVisitor.last_seen)).all()]

@app.get("/api/live-visitors")
def visitors(db:Session=Depends(get_db)):
    mark_stale_visitors(db)
    iot_visitors=[public_iot_visitor(x) for x in db.query(Device).order_by(desc(Device.last_seen)).all()]
    web_visitors=[public_web_visitor(x) for x in db.query(WebVisitor).filter_by(online=True).order_by(desc(WebVisitor.last_seen)).all()]
    return iot_visitors+web_visitors
@app.get("/api/admin/live-visitors")
def admin_live_visitors(db:Session=Depends(get_db)):
    mark_stale_visitors(db)
    web=[]
    for visitor in db.query(WebVisitor).filter_by(online=True).all():
        item=public_web_visitor(visitor,include_ip=True)
        item["name"]=f"Visitor {visitor.visitor_id} · IP: {visitor.ip_address or 'Unknown'}"
        if visitor.device_name and visitor.device_name!="Unknown": item["device_type"]=f"{visitor.device_type} · {visitor.device_name}"
        if visitor.browser_version and visitor.browser_version!="Unknown": item["browser"]=f"{visitor.browser} {visitor.browser_version}"
        web.append(item)
    return [public_iot_visitor(x) for x in db.query(Device).all()]+web
@app.get("/api/admin/live-visitors/{visitor_id}")
def admin_live_visitor(visitor_id:str, db:Session=Depends(get_db)):
    device=db.get(Device,visitor_id)
    if device: return public_iot_visitor(device)
    mark_stale_visitors(db)
    visitor=db.get(WebVisitor,visitor_id)
    if not visitor: raise HTTPException(404,"Visitor not found")
    item=public_web_visitor(visitor,include_ip=True)
    item["name"]=f"Visitor {visitor.visitor_id} · IP: {visitor.ip_address or 'Unknown'}"
    return item
@app.get("/api/location-data")
def locations(db:Session=Depends(get_db)):
    mark_stale_visitors(db)
    iot_locations=[{"device_id":x.id,"visitor_type":"IOT","latitude":x.latitude,"longitude":x.longitude,"risk_score":x.risk_score,"tamper":x.tamper_detected,"online":x.online,"last_seen":iso_timestamp(x.last_seen)} for x in db.query(Device).all()]
    web_locations=[{"device_id":x.visitor_id,"visitor_type":"ONLINE","latitude":x.latitude,"longitude":x.longitude,"risk_score":None,"tamper":False,"online":x.online,"last_seen":iso_timestamp(x.last_seen)} for x in db.query(WebVisitor).filter(WebVisitor.online.is_(True),WebVisitor.latitude.is_not(None),WebVisitor.longitude.is_not(None)).all()]
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
