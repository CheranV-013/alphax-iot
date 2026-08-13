import sys, random
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent.parent/"backend"))
from datetime import datetime,timezone,timedelta
from app.database import Base,engine,SessionLocal
from app.models import User,Device,Transaction
from app.main import evaluate
random.seed(7); Base.metadata.create_all(engine); db=SessionLocal()
if db.query(User).count()==0:
    for i in range(12): db.add(User(id=f"USR-{i+1:03}",name=["Aisha Khan","Rohan Iyer","Maya Chen","Daniel Ross"][i%4],email=f"user{i+1}@demo.local",baseline_spend=random.choice([80,120,220])))
    locations=[(11.0168,76.9558),(11.018,76.96),(11.01,76.948),(11.025,76.97),(11.0,76.94)]
    for i,(la,lo) in enumerate(locations,1): db.add(Device(id=f"ESP{i:03}",name=f"Terminal {i}",expected_latitude=la,expected_longitude=lo,latitude=la,longitude=lo))
    db.commit()
if db.query(Transaction).count()<100:
    users=db.query(User).all(); devs=db.query(Device).all(); base=datetime.now(timezone.utc)-timedelta(hours=48)
    for i in range(120):
        u=random.choice(users); d=random.choice(devs); suspicious=i%13==0; la=d.latitude+(random.uniform(1,4) if suspicious else random.uniform(-.005,.005)); lo=d.longitude+(random.uniform(1,4) if suspicious else random.uniform(-.005,.005)); tx=Transaction(id=f"TXN-{1000+i}",user_id=u.id,amount=random.uniform(500,900) if suspicious else random.uniform(12,260),timestamp=base+timedelta(minutes=i*24),merchant=random.choice(["NovaMart","CloudNine","MetroPay","Orbit Retail"]),ip_address=random.choice(["185.22.10.4","45.91.4.7","10.0.0.8","192.168.1.4"]),device_id=d.id,latitude=la,longitude=lo,transaction_velocity=random.uniform(8,14) if suspicious else random.uniform(1,4)); db.add(tx); db.commit(); evaluate(db,tx)
db.close(); print("Seeded demo database")

