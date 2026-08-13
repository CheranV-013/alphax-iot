import json, math
from datetime import datetime, timezone
from .config import settings

def distance_km(a,b,c,d):
    r=6371; p=math.pi/180; x=(c-a)*p*math.cos((a+b)*p/2); y=(d-b)*p; return math.sqrt(x*x+y*y)*r

def assess(tx, user, device, ml, model_amount=None):
    location_change=distance_km(user.get("last_lat",tx.latitude),user.get("last_lon",tx.longitude),tx.latitude,tx.longitude)
    ip_score=0.78 if tx.ip_address.startswith(("185.","45.","103.")) else 0.12
    known_device=tx.device_id in user.get("devices",[]); device_score=0.82 if not known_device else .08
    velocity=min(float(tx.transaction_velocity)/10,1); behaviour=min(abs(tx.amount-user.get("baseline",100))/(user.get("baseline",100)*2),1)
    loc_score=min(location_change/80,1)
    tamper=1.0 if device and device.tamper_detected else 0.0
    amount_threshold_score=1.0 if tx.amount>=settings.transaction_limit else 0.0
    features={"amount":tx.amount if model_amount is None else model_amount,"velocity":tx.transaction_velocity,"device_change":int(not known_device),"location_change":location_change,"ip_risk":ip_score,"spend_deviation":(tx.amount-user.get("baseline",100))/max(user.get("baseline",100),1),"hour":tx.timestamp.hour}
    fraud, anomaly=ml.infer(features)
    parts={"Fraud probability":fraud,"Anomaly detection":anomaly,"Unusual behaviour":behaviour,"IP reputation":ip_score,"New device":device_score,"Location anomaly":loc_score,"IoT tamper":tamper,"Amount threshold":amount_threshold_score}
    base=.25*fraud+.20*anomaly+.15*behaviour+.10*ip_score+.10*device_score+.10*loc_score+.10*tamper
    threshold_weight=settings.amount_threshold_weight if amount_threshold_score else 0
    score=100*((1-threshold_weight)*base+threshold_weight*amount_threshold_score)
    if amount_threshold_score: score=max(score,40.0)
    decision="BLOCK" if score>=70 else "REVIEW" if score>=40 else "ALLOW"
    explanation=json.dumps(sorted(parts.items(), key=lambda x:x[1], reverse=True))
    return {"fraud_probability":fraud,"anomaly_score":anomaly,"behaviour_score":behaviour,"ip_score":ip_score,"device_score":device_score,"location_score":loc_score,"iot_tamper_score":tamper,"final_risk_score":score,"decision":decision,"explanation":explanation}
